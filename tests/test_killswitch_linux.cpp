#include "fwmark.h"
#include "killswitch_linux.h"
#include "net/ip.h"
#include "net/iptables.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *TUN_DEV = "kstun0";

        bool ip(const std::vector<std::string> &args)
        {
            for (const char *path : { "/usr/sbin/ip", "/sbin/ip" }) {
                if (::access(path, X_OK) == 0) {
                    return static_cast<bool>(spawn::run(path, args, {}));
                }
            }
            return false;
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        if (!privileged()) {
            m_skipReason = "network namespaces and iptables require root";
            return;
        }

        for (const std::string name : { "iptables-restore", "ip6tables-restore" }) {
            if (::access(("/usr/sbin/" + name).c_str(), X_OK) != 0 && ::access(("/sbin/" + name).c_str(), X_OK) != 0) {
                m_skipReason = name + " is missing";
                return;
            }
        }

        m_netnsFd = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        if (m_netnsFd < 0 || ::unshare(CLONE_NEWNET) != 0) {
            m_skipReason = "could not create a private network namespace";
            return;
        }

        auto uplinkTun = createTun();
        auto clientTun = createTun();
        if (!uplinkTun || !uplinkTun->first || !clientTun || !clientTun->first) {
            m_skipReason = "could not open the tun devices for the fake uplink and the client side";
            return;
        }
        m_uplinkFd = std::move(uplinkTun->first);
        m_clientFd = std::move(clientTun->first);

        const std::string up = uplinkTun->second;
        const std::string client = clientTun->second;
        const std::string tun(TUN_DEV);
        const std::vector<std::vector<std::string>> setup {
            { "link", "set", "lo", "up" },
            { "addr", "add", FAKE_UPLINK_V4, "dev", up },
            { "-6", "addr", "add", FAKE_UPLINK_V6, "dev", up, "nodad" },
            { "link", "set", up, "up" },
            { "route", "add", "default", "dev", up },
            { "-6", "route", "add", "default", "dev", up },
            { "route", "add", HIJACKED.host, "dev", up },
            { "addr", "add", CLIENT_V4, "dev", client },
            { "link", "set", client, "up" },
            { "link", "add", tun, "type", "dummy" },
            { "link", "set", tun, "up" },
        };
        if (!std::ranges::all_of(setup, ip)) {
            m_skipReason = "could not set up the fake uplink: needs the 'tun' and 'dummy' kernel modules and IPv6";
            return;
        }

        std::ofstream("/proc/sys/net/ipv4/ip_forward") << '1';
        m_forwarding = std::ifstream("/proc/sys/net/ipv4/ip_forward").get() == '1';

        m_uplinkReader = std::thread([this] {
            ::pollfd ready { m_uplinkFd.get(), POLLIN, 0 };
            std::array<std::byte, 2048> packet {};
            while (!m_stopReader) {
                if (::poll(&ready, 1, static_cast<int>(PROBE_SLICE.count())) <= 0) {
                    continue;
                }
                const ssize_t size = ::read(m_uplinkFd.get(), packet.data(), packet.size());
                if (size <= 0) {
                    continue;
                }
                const std::vector<std::byte> reply =
                        handleUplinkPacket(std::span(packet.data(), static_cast<std::size_t>(size)));
                if (!reply.empty()) {
                    [[maybe_unused]] const ssize_t written = ::write(m_uplinkFd.get(), reply.data(), reply.size());
                }
            }
        });
        m_ifName = tun;
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_uplinkReader.joinable()) {
            m_stopReader = true;
            m_uplinkReader.join();
        }
        if (m_netnsFd >= 0) {
            ::setns(m_netnsFd, CLONE_NEWNET);
            ::close(m_netnsFd);
        }
    }

    int KillswitchEnv::ruleCount() const
    {
        const auto chainCount = [](int family, const char *table, const char *builtin, const char *chain) {
            int count = iptables::run(family, { "-t", table, "-C", builtin, "-j", chain }) == LIBXTUN_OK ? 1 : 0;
            const auto rules = iptables::rules(family, table, chain);
            std::istringstream lines(rules ? rules.value() : std::string {});
            for (std::string line; std::getline(lines, line);) {
                if (line.starts_with("-N ") || line.starts_with("-A ")) {
                    ++count;
                }
            }
            return count;
        };

        int count = 0;
        for (const int family : { AF_INET, AF_INET6 }) {
            count += chainCount(family, "filter", "OUTPUT", CHAIN);
            count += chainCount(family, "mangle", "FORWARD", FORWARD_CHAIN);
        }
        return count;
    }

    std::optional<ProbeResult> KillswitchEnv::connect(const std::string &host, std::uint16_t port, Sender sender) const
    {
        const ConnectedSocket tcp = tcpConnect(host, port, PROBE_TIMEOUT, sender == Sender::Proxy ? PROXY_FWMARK : 0);
        if (tcp.error == 0) {
            return localAddress(tcp.fd) == DEFAULT_IFADDR ? ProbeResult::Tunnel : ProbeResult::Uplink;
        }
        if (tcp.error == ECONNREFUSED || tcp.error == ETIMEDOUT) {
            return ProbeResult::Blocked;
        }

        ADD_FAILURE() << "the probe to " << host << ' ' << sender << " failed: " << std::strerror(tcp.error);
        return std::nullopt;
    }

    bool KillswitchEnv::injectSyn(const net::IpAddress &destination, std::uint16_t sport) const
    {
        if (!m_forwarding) {
            ADD_FAILURE() << "IPv4 forwarding stayed off, /proc/sys may be read-only";
            return false;
        }

        const std::vector<std::byte> syn = forwardedSyn(destination, sport);
        if (::write(m_clientFd.get(), syn.data(), syn.size()) != static_cast<ssize_t>(syn.size())) {
            ADD_FAILURE() << "could not inject the forwarded probe: " << std::strerror(errno);
            return false;
        }
        return true;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::string tunnel = ifnameFromAddr(DEFAULT_IFADDR);
        if (tunnel.empty()) {
            return false;
        }

        return std::ranges::all_of(routes, [&tunnel](const std::string &route) {
            return route == "0.0.0.0/0" ? ip({ "route", "flush", "table", std::to_string(PROXY_TABLE) })
                                        : ip({ "route", "del", route, "dev", tunnel });
        });
    }
}
