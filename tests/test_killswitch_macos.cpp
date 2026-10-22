#include "killswitch_macos.h"
#include "net/ip.h"
#include "net/pf.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"
#include "util/spawn.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *PROBE_IFACE = "utun9";
        constexpr const char *FAKE_UPLINK_PEER = "10.10.0.1";
        constexpr const char *FORWARDING = "net.inet.ip.forwarding";
        constexpr ::gid_t FOREIGN_GID = 1;
        constexpr std::size_t UTUN_HEADER_SIZE = 4;

        std::vector<std::byte> utunFrame(std::span<const std::byte> packet)
        {
            const bool v6 = !packet.empty() && std::to_integer<unsigned>(packet[0]) >> 4 == 6;
            const std::uint32_t family = htonl(v6 ? AF_INET6 : AF_INET);
            std::vector<std::byte> frame(UTUN_HEADER_SIZE);
            std::memcpy(frame.data(), &family, sizeof(family));
            frame.insert(frame.end(), packet.begin(), packet.end());
            return frame;
        }

        int getForwarding()
        {
            int value = 0;
            std::size_t size = sizeof(value);
            return ::sysctlbyname(FORWARDING, &value, &size, nullptr, 0) == 0 ? value : -1;
        }

        bool setForwarding(int value)
        {
            return ::sysctlbyname(FORWARDING, nullptr, nullptr, &value, sizeof(value)) == 0;
        }

        bool ifconfig(const std::vector<std::string> &args)
        {
            return static_cast<bool>(spawn::run("/sbin/ifconfig", args, {}));
        }

        bool route(const std::vector<std::string> &args)
        {
            return static_cast<bool>(spawn::run("/sbin/route", args, {}));
        }

        std::string defaultRoute(const std::string &field)
        {
            const auto output = spawn::run("/sbin/route", { "-n", "get", "default" }, {});
            std::istringstream lines(output ? output.value() : std::string {});
            for (std::string line; std::getline(lines, line);) {
                if (const std::size_t at = line.find(field + ':'); at != std::string::npos) {
                    std::istringstream value(line.substr(at + field.size() + 1));
                    std::string result;
                    value >> result;
                    return result;
                }
            }
            return {};
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

        int connectInChild(const ::addrinfo &target, const in_addr &tunnel, int timeoutMs)
        {
            if (::setegid(FOREIGN_GID) != 0) {
                return errno;
            }
            const ScopedFd sock(::socket(target.ai_family, target.ai_socktype, target.ai_protocol));
            if (!sock || ::fcntl(sock.get(), F_SETFL, ::fcntl(sock.get(), F_GETFL) | O_NONBLOCK) != 0) {
                return errno;
            }
            if (::connect(sock.get(), target.ai_addr, target.ai_addrlen) != 0) {
                if (errno != EINPROGRESS) {
                    return errno;
                }
                ::pollfd ready { sock.get(), POLLOUT, 0 };
                const int events = ::poll(&ready, 1, timeoutMs);
                if (events == 0) {
                    return ETIMEDOUT;
                }
                if (events < 0) {
                    return errno;
                }
                int error = 0;
                ::socklen_t errorSize = sizeof(error);
                if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &error, &errorSize) != 0) {
                    return errno;
                }
                if (error != 0) {
                    return error;
                }
            }

            ::sockaddr_storage local {};
            ::socklen_t localSize = sizeof(local);
            if (::getsockname(sock.get(), reinterpret_cast<::sockaddr *>(&local), &localSize) != 0) {
                return errno;
            }
            const bool viaTunnel = local.ss_family == AF_INET
                    && reinterpret_cast<const ::sockaddr_in &>(local).sin_addr.s_addr == tunnel.s_addr;
            return viaTunnel ? CONNECTED_VIA_TUNNEL : CONNECTED_ELSEWHERE;
        }

        int connectAsForeignGroup(const std::string &host, std::uint16_t port)
        {
            ::addrinfo hints {};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

            ::addrinfo *resolved = nullptr;
            if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &resolved) != 0) {
                return EADDRNOTAVAIL;
            }
            in_addr tunnel {};
            ::inet_pton(AF_INET, DEFAULT_IFADDR, &tunnel);

            const ::pid_t child = ::fork();
            if (child == 0) {
                ::_exit(connectInChild(*resolved, tunnel, static_cast<int>(PROBE_TIMEOUT.count())));
            }

            const int forkError = child < 0 ? errno : 0;
            ::freeaddrinfo(resolved);
            if (forkError != 0) {
                return forkError;
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
    }

    KillswitchEnv::KillswitchEnv(bool realEndpoint) : m_realEndpoint(realEndpoint)
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

        const std::string gateway = defaultRoute("gateway");
        if (gateway.empty()) {
            m_skipReason = "no IPv4 default gateway";
            return;
        }

        auto fake = createTun();
        auto client = createTun();
        if (!fake || !fake->first || !client || !client->first) {
            m_skipReason = "could not open the utuns for the fake uplink and the client side";
            return;
        }
        if (fake->second == PROBE_IFACE || client->second == PROBE_IFACE) {
            m_skipReason = "a test utun took the name the killswitch exempts";
            return;
        }
        m_uplinkFd = std::move(fake->first);
        m_clientFd = std::move(client->first);

        const std::string up = fake->second;
        const std::string side = client->second;
        if (!(ifconfig({ up, "inet", FAKE_UPLINK_V4, FAKE_UPLINK_PEER, "up" })
              && ifconfig({ up, "inet6", FAKE_UPLINK_V6, "alias" })
              && route({ "-q", "-n", "add", "-host", LAN.host, "-interface", up })
              && route({ "-q", "-n", "add", "-host", HIJACKED.host, "-interface", up })
              && route({ "-q", "-n", "add", "-inet6", "-host", INTERNET_V6.host, "-interface", up })
              && ifconfig({ side, "inet", CLIENT_V4, FORWARDED_SOURCE, "up" }))) {
            m_skipReason = "could not set up the fake uplink and the client side utuns";
            return;
        }
        const std::string uplink = m_realEndpoint ? defaultRoute("interface") : up;
        m_uplinkIfIndex = ::if_nametoindex(uplink.c_str());
        if (m_uplinkIfIndex == 0) {
            m_skipReason = "could not look up the uplink " + uplink;
            return;
        }

        if (!m_realEndpoint) {
            if (!route({ "-q", "-n", "change", "default", FAKE_UPLINK_PEER })) {
                m_skipReason = "could not move the default route to the fake uplink";
                return;
            }
            m_originalGateway = gateway;
        }

        m_restoreForwarding = !m_realEndpoint && getForwarding() == 0 && setForwarding(1);
        m_ifName = PROBE_IFACE;
        pf::flushRules(ANCHOR);

        m_uplinkReader = std::thread([this] {
            ::pollfd ready { m_uplinkFd.get(), POLLIN, 0 };
            std::array<std::byte, 2048> buffer {};
            while (!m_stopReader) {
                if (::poll(&ready, 1, static_cast<int>(PROBE_SLICE.count())) <= 0) {
                    continue;
                }
                const ssize_t size = ::read(m_uplinkFd.get(), buffer.data(), buffer.size());
                if (size <= static_cast<ssize_t>(UTUN_HEADER_SIZE)) {
                    continue;
                }
                const std::vector<std::byte> reply = handleUplinkPacket(
                        std::span(buffer.data() + UTUN_HEADER_SIZE, static_cast<std::size_t>(size) - UTUN_HEADER_SIZE));
                if (!reply.empty()) {
                    const std::vector<std::byte> frame = utunFrame(reply);
                    [[maybe_unused]] const ssize_t written = ::write(m_uplinkFd.get(), frame.data(), frame.size());
                }
            }
        });
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_uplinkReader.joinable()) {
            m_stopReader = true;
            m_uplinkReader.join();
        }
        if (!m_originalGateway.empty()) {
            route({ "-q", "-n", "change", "default", m_originalGateway });
        }
        if (m_skipReason.empty()) {
            pf::flushRules(ANCHOR);
        }
        if (m_restoreForwarding) {
            setForwarding(0);
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

    std::optional<ProbeResult> KillswitchEnv::connect(const std::string &host, std::uint16_t port, Sender sender) const
    {
        int code = 0;
        if (sender == Sender::App) {
            code = connectAsForeignGroup(host, port);
        } else {
            const ConnectedSocket tcp = tcpConnect(host, port, PROBE_TIMEOUT, m_uplinkIfIndex);
            code = tcp.error;
            if (code == 0) {
                code = localAddress(tcp.fd) == DEFAULT_IFADDR ? CONNECTED_VIA_TUNNEL : CONNECTED_ELSEWHERE;
            }
        }

        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case ECONNREFUSED:
        case EHOSTUNREACH:
        case EINVAL:
        case EPERM:
        case ETIMEDOUT: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << host << ' ' << sender << " failed: " << std::strerror(code);
        return std::nullopt;
    }

    bool KillswitchEnv::injectSyn(const net::IpAddress &destination, std::uint16_t sport) const
    {
        if (getForwarding() != 1) {
            ADD_FAILURE() << "IPv4 forwarding is off";
            return false;
        }

        const std::vector<std::byte> frame = utunFrame(forwardedSyn(destination, sport));
        if (::write(m_clientFd.get(), frame.data(), frame.size()) != static_cast<ssize_t>(frame.size())) {
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
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_SOFT, static_cast<int>(::getegid()));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);

            expectProbeResult(INTERNET_V4, Sender::Proxy, ProbeResult::Uplink, "with the process's group");
            expectProbeResult(INTERNET_V4, Sender::App, ProbeResult::Blocked, "with the process's group");
        }
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_SOFT, static_cast<int>(FOREIGN_GID));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);

            expectProbeResult(INTERNET_V4, Sender::App, ProbeResult::Uplink, "with the foreign group");
            expectProbeResult(INTERNET_V4, Sender::Proxy, ProbeResult::Blocked, "with the foreign group");
        }
    }
}
