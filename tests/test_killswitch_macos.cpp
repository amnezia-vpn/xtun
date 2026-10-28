#include "health/dns_query.h"
#include "killswitch_macos.h"
#include "net/ip.h"
#include "net/pf.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"
#include "util/spawn.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *PROBE_IFACE = "utun9";
        constexpr ::gid_t FOREIGN_GID = 1;
        constexpr const char *UPLINK_ULA = "fd00:7874::2";
        constexpr auto ANSWER_WAIT = std::chrono::milliseconds(1000);

        bool ifconfig(const std::vector<std::string> &args)
        {
            return static_cast<bool>(spawn::run("/sbin/ifconfig", args, {}));
        }

        bool route(const std::vector<std::string> &args)
        {
            return static_cast<bool>(spawn::run("/sbin/route", args, {}));
        }

        std::string anchorRules()
        {
            const auto rules = pf::pfctl({ "-a", ANCHOR, "-s", "rules" }, {});
            return rules ? rules.value() : std::string {};
        }

        std::string protectedEntries()
        {
            const auto entries = pf::pfctl({ "-a", ANCHOR, "-t", PROTECTED_TABLE, "-T", "show" }, {});
            return entries ? entries.value() : std::string {};
        }

        template<typename F> int runAsForeignGroup(F &&probe)
        {
            const ::pid_t child = ::fork();
            if (child == 0) {
                ::_exit(::setegid(FOREIGN_GID) != 0 ? errno : probe());
            }
            if (child < 0) {
                return errno;
            }

            int status = 0;
            pid_t r;

            do {
                r = ::waitpid(child, &status, 0);
            } while (r == -1 && errno == EINTR);

            if (r < 0 || !WIFEXITED(status)) {
                return ECHILD;
            }
            return WEXITSTATUS(status);
        }

        bool answered(const std::string &host, std::uint16_t port, bool tcp)
        {
            if (tcp) {
                return tcpConnect(host, port, ANSWER_WAIT).error == 0;
            }

            const ConnectedSocket udp = udpConnect(host, port);
            const health::DnsQuery query(0x1234, 0xdeadbeef);
            if (udp.error != 0 || ::send(udp.fd.get(), query.bytes().data(), query.bytes().size(), 0) < 0) {
                return false;
            }
            ::pollfd ready { udp.fd.get(), POLLIN, 0 };
            std::array<std::byte, 512> reply {};
            return ::poll(&ready, 1, static_cast<int>(ANSWER_WAIT.count())) > 0
                    && ::recv(udp.fd.get(), reply.data(), reply.size(), 0) > 0;
        }

        std::string defaultInterface()
        {
            const auto output = spawn::run("/sbin/route", { "-n", "get", "default" }, {});
            std::istringstream words(output ? output.value() : std::string {});
            for (std::string word; words >> word;) {
                if (word == "interface:" && words >> word) {
                    return word;
                }
            }
            return {};
        }

        bool waitForUla()
        {
            ::sockaddr_in6 ula {};
            ula.sin6_len = sizeof(ula);
            ula.sin6_family = AF_INET6;
            ::inet_pton(AF_INET6, UPLINK_ULA, &ula.sin6_addr);
            const ScopedFd sock(::socket(AF_INET6, SOCK_DGRAM, 0));
            for (int attempt = 0; attempt < 30; ++attempt) {
                if (::bind(sock.get(), reinterpret_cast<const ::sockaddr *>(&ula), sizeof(ula)) == 0) {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            return false;
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        if (!privileged()) {
            m_skipReason = "loading pf anchors requires root";
            return;
        }
        if (::getegid() == FOREIGN_GID) {
            m_skipReason = "the probe group must differ from the installing group";
            return;
        }

        const auto rules = pf::pfctl({ "-s", "rules" }, {});
        if (!rules || rules.value().find(pf::ANCHOR_REF) == std::string::npos) {
            m_skipReason = "the main pf ruleset does not reference com.apple/*";
            return;
        }

        const std::string uplink = defaultInterface();
        m_uplinkIfIndex = ::if_nametoindex(uplink.c_str());
        if (m_uplinkIfIndex == 0) {
            m_skipReason = "no IPv4 default route";
            return;
        }
        route({ "-q", "-n", "delete", "-inet6", "-host", INTERNET_V6.host });
        if (!route({ "-q", "-n", "add", "-inet6", "-host", INTERNET_V6.host, "-interface", uplink })) {
            m_skipReason = "could not route " + INTERNET_V6.host + " through " + uplink + ", IPv6 may be disabled";
            return;
        }
        ifconfig({ uplink, "inet6", UPLINK_ULA, "delete" });
        if (!ifconfig({ uplink, "inet6", std::string(UPLINK_ULA) + "/64", "alias" }) || !waitForUla()) {
            m_skipReason = "could not add a usable " + std::string(UPLINK_ULA) + " to " + uplink;
            return;
        }

        m_ifName = PROBE_IFACE;
        pf::flushRules(ANCHOR);
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_skipReason.empty()) {
            pf::flushRules(ANCHOR);
            route({ "-q", "-n", "delete", "-inet6", "-host", INTERNET_V6.host });
            std::array<char, IF_NAMESIZE> uplink {};
            ::if_indextoname(m_uplinkIfIndex, uplink.data());
            ifconfig({ uplink.data(), "inet6", UPLINK_ULA, "delete" });
        }
    }

    int KillswitchEnv::ruleCount() const
    {
        std::istringstream rules(anchorRules());
        int count = 0;
        for (std::string line; std::getline(rules, line);) {
            if (line.starts_with("pass") || line.starts_with("block")) {
                ++count;
            }
        }

        std::istringstream entries(protectedEntries());
        for (std::string entry; entries >> entry;) {
            if (net::IpPrefix::parse(entry)) {
                ++count;
            }
        }
        return count;
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const Destination &to, Sender sender, std::uint16_t port) const
    {
        const bool tcp = port == DNS_TLS_PORT;
        const bool dns = tcp || port == DNS_PORT;
        const auto sendProbe = [&](unsigned bypass) {
            const int probeCode = tcp ? tcpProbe(to.host, port, bypass) : udpProbe(to.host, port, bypass);
            if (dns && probeCode == CONNECTED_VIA_TUNNEL && !answered(to.host, port, tcp)) {
                return EPERM;
            }
            return probeCode;
        };
        const int code = sender == Sender::App ? runAsForeignGroup([&] { return sendProbe(0); }) : sendProbe(m_uplinkIfIndex);
        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case ECONNREFUSED:
        case EHOSTUNREACH:
        case EINVAL:
        case EPERM: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << to.host << ' ' << sender << " failed: " << std::strerror(code);
        return std::nullopt;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::string tunnel = ifnameFromAddr(DEFAULT_IFADDR);
        if (tunnel.empty()) {
            return false;
        }

        for (const std::string &profileRoute : routes) {
            const std::vector<std::string> prefixes = profileRoute == "0.0.0.0/0"
                    ? std::vector<std::string> { "0.0.0.0/1", "128.0.0.0/1" }
                    : std::vector<std::string> { profileRoute };
            for (const std::string &prefix : prefixes) {
                if (!route({ "-q", "-n", "delete", "-net", prefix, "-interface", tunnel })) {
                    return false;
                }
            }
        }
        return true;
    }

    using KillswitchMacos = KillswitchTest;

    TEST_F(KillswitchMacos, ConfiguredGroupIsExcluded)
    {
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_HARD, static_cast<int>(::getegid()));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);
            ASSERT_EQ(killswitch->protect({ *net::IpPrefix::parse("0.0.0.0/0") }, {}), LIBXTUN_OK);

            expectProbeResult(INTERNET_V4, Sender::Proxy, ProbeResult::Uplink, "with the process's group");
            expectProbeResult(INTERNET_V4, Sender::App, ProbeResult::Blocked, "with the process's group");
        }
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_HARD, static_cast<int>(FOREIGN_GID));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);
            ASSERT_EQ(killswitch->protect({ *net::IpPrefix::parse("0.0.0.0/0") }, {}), LIBXTUN_OK);

            expectProbeResult(INTERNET_V4, Sender::App, ProbeResult::Uplink, "with the foreign group");
            expectProbeResult(INTERNET_V4, Sender::Proxy, ProbeResult::Blocked, "with the foreign group");
        }
    }
}
