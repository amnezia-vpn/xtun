#include "killswitch_macos.h"
#include "net/ip.h"
#include "net/pf.h"
#include "util/killswitch_env.h"
#include "util/os.h"
#include "util/spawn.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
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
        constexpr int MAX_TAP_UNITS = 256;
        constexpr unsigned TAP_BUFFER_SIZE = 32768;
        constexpr std::size_t UTUN_HEADER_SIZE = 4;

        ScopedFd tapOn(const std::string &ifName)
        {
            for (int unit = 0; unit < MAX_TAP_UNITS; ++unit) {
                ScopedFd tap(::open(("/dev/bpf" + std::to_string(unit)).c_str(), O_RDONLY | O_CLOEXEC));
                if (!tap) {
                    if (errno == EBUSY) {
                        continue;
                    }
                    return ScopedFd {};
                }

                ::ifreq request {};
                std::strncpy(request.ifr_name, ifName.c_str(), sizeof(request.ifr_name) - 1);
                unsigned bufferSize = TAP_BUFFER_SIZE;
                unsigned on = 1;
                if (::ioctl(tap.get(), BIOCSBLEN, &bufferSize) != 0 || bufferSize != TAP_BUFFER_SIZE
                    || ::ioctl(tap.get(), BIOCSETIF, &request) != 0 || ::ioctl(tap.get(), BIOCIMMEDIATE, &on) != 0
                    || ::ioctl(tap.get(), BIOCSSEESENT, &on) != 0) {
                    return ScopedFd {};
                }
                return tap;
            }
            return ScopedFd {};
        }

        void drain(const ScopedFd &source)
        {
            ::pollfd ready { source.get(), POLLIN, 0 };
            std::vector<std::byte> buffer(TAP_BUFFER_SIZE);
            while (::poll(&ready, 1, 0) > 0 && ::read(source.get(), buffer.data(), buffer.size()) > 0) {
            }
        }

        std::string defaultInterface()
        {
            const ConnectedSocket probe = udpConnect(TEST_NET_V4, PROBE_PORT);
            ::sockaddr_in local {};
            ::socklen_t size = sizeof(local);
            if (probe.error != 0 || ::getsockname(probe.fd.get(), reinterpret_cast<::sockaddr *>(&local), &size) != 0) {
                return {};
            }

            std::array<char, INET_ADDRSTRLEN> address {};
            if (::inet_ntop(AF_INET, &local.sin_addr, address.data(), address.size()) == nullptr) {
                return {};
            }
            return ifnameFromAddr(address.data());
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

        int sendBound(const std::string &host, std::uint16_t port, unsigned ifIndex, const Nonce &nonce)
        {
            ::addrinfo hints {};
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

            ::addrinfo *resolved = nullptr;
            if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &resolved) != 0) {
                return EINVAL;
            }
            const std::unique_ptr<::addrinfo, decltype(&::freeaddrinfo)> owner(resolved, ::freeaddrinfo);

            const ScopedFd sock(::socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol));
            if (!sock) {
                return errno;
            }
            const bool v6 = resolved->ai_family == AF_INET6;
            if (::setsockopt(sock.get(), v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_BOUND_IF : IP_BOUND_IF, &ifIndex,
                             sizeof(ifIndex))
                        != 0
                || ::connect(sock.get(), resolved->ai_addr, resolved->ai_addrlen) != 0
                || ::send(sock.get(), nonce.data(), nonce.size(), 0) < 0) {
                return errno;
            }
            return 0;
        }

        int sendAsForeignGroup(const std::string &host, std::uint16_t port, const Nonce &nonce)
        {
            ::addrinfo hints {};
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

            ::addrinfo *resolved = nullptr;
            if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &resolved) != 0) {
                return EINVAL;
            }

            const ::pid_t child = ::fork();
            if (child == 0) {
                int error = 0;
                if (::setegid(FOREIGN_GID) != 0) {
                    error = errno;
                } else if (const int sock = ::socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
                           sock < 0) {
                    error = errno;
                } else if (::connect(sock, resolved->ai_addr, resolved->ai_addrlen) != 0) {
                    error = errno;
                } else if (::send(sock, nonce.data(), nonce.size(), 0) < 0) {
                    error = errno;
                }
                ::_exit(error);
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
        m_defaultIfIndex = uplink.empty() ? 0 : ::if_nametoindex(uplink.c_str());
        if (m_defaultIfIndex == 0) {
            m_skipReason = "no uplink to probe through";
            return;
        }
        m_tap = tapOn(uplink);
        if (!m_tap) {
            m_skipReason = "could not tap the uplink " + uplink;
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
              && route({ "-q", "-n", "add", "-net", LAN_PREFIX, "-interface", up })
              && route({ "-q", "-n", "add", "-net", HIJACKED_PREFIX, "-interface", up })
              && route({ "-q", "-n", "add", "-inet6", TEST_NET_V6_PREFIX, "-interface", up })
              && ifconfig({ side, "inet", CLIENT_SIDE_V4, FORWARDED_SOURCE, "up" }))) {
            m_skipReason = "could not set up the fake uplink and the client side utuns";
            return;
        }

        m_restoreForwarding = getForwarding() == 0 && setForwarding(1);
        m_ifName = PROBE_IFACE;
        pf::flushRules(ANCHOR);
    }

    KillswitchEnv::~KillswitchEnv()
    {
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

    SendResult KillswitchEnv::send(const std::string &host, std::uint16_t port, Sender sender, const Nonce &nonce) const
    {
        drain(m_tap);
        drain(m_uplinkFd);

        int error = 0;
        switch (sender) {
        case Sender::App: error = sendAsForeignGroup(host, port, nonce); break;
        case Sender::Proxy: error = sendBound(host, port, m_defaultIfIndex, nonce); break;
        case Sender::Forwarded: {
            if (getForwarding() != 1) {
                ADD_FAILURE() << "IPv4 forwarding is off";
                return SendResult::Failed;
            }
            const std::optional<net::IpAddress> destination = net::IpAddress::parse(host);
            if (!destination || destination->family() != AF_INET) {
                ADD_FAILURE() << "forwarded probes are IPv4 only, got " << host;
                return SendResult::Failed;
            }

            const std::uint32_t family = htonl(AF_INET);
            std::vector<std::byte> packet(UTUN_HEADER_SIZE);
            std::memcpy(packet.data(), &family, sizeof(family));
            const std::vector<std::byte> datagram = forwardedPacket(*destination, port, nonce);
            packet.insert(packet.end(), datagram.begin(), datagram.end());
            if (::write(m_clientFd.get(), packet.data(), packet.size()) != static_cast<ssize_t>(packet.size())) {
                error = errno;
            }
            break;
        }
        }

        if (error == 0) {
            return SendResult::Out;
        }
        if (error == EPERM) {
            return SendResult::Refused;
        }

        ADD_FAILURE() << "the probe to " << host << ' ' << sender << " failed: " << std::strerror(error);
        return SendResult::Failed;
    }

    std::optional<ProbeResult> KillswitchEnv::pollUplink(const Destination &to, const Nonce &nonce) const
    {
        const ScopedFd &source = to.viaDefault ? m_tap : m_uplinkFd;
        ::pollfd ready { source.get(), POLLIN, 0 };
        std::vector<std::byte> buffer(TAP_BUFFER_SIZE);
        int wait = static_cast<int>(PROBE_SLICE.count());
        while (::poll(&ready, 1, wait) > 0) {
            const ssize_t size = ::read(source.get(), buffer.data(), buffer.size());
            if (size > static_cast<ssize_t>(UTUN_HEADER_SIZE)) {
                const std::span<const std::byte> data(buffer.data(), static_cast<std::size_t>(size));
                if (to.viaDefault ? containsNonce(data, nonce)
                                  : udpPktContainsNonce(data.subspan(UTUN_HEADER_SIZE), nonce)) {
                    return ProbeResult::Uplink;
                }
            }
            wait = 0;
        }
        return std::nullopt;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::string tunnel = ifnameFromAddr(TUNNEL_ADDRESS);
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
