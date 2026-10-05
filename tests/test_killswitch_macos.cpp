#include "killswitch_macos.h"
#include "net/pf.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
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
        constexpr ::gid_t FOREIGN_GID = 1;
        constexpr int MAX_TAP_UNITS = 256;
        constexpr unsigned TAP_BUFFER_SIZE = 32768;
        constexpr auto PROBE_TIMEOUT = std::chrono::milliseconds(500);

        using Nonce = std::array<std::byte, 16>;

        class ProbeTap : private NonCopyable
        {
        public:
            ProbeTap()
            {
                ::ifaddrs *list = nullptr;
                if (::getifaddrs(&list) != 0) {
                    ADD_FAILURE() << "could not list the interfaces to tap";
                    return;
                }

                const std::unique_ptr<::ifaddrs, decltype(&::freeifaddrs)> interfaces(list, ::freeifaddrs);
                for (const ::ifaddrs *it = interfaces.get(); it != nullptr; it = it->ifa_next) {
                    if (it->ifa_addr == nullptr || it->ifa_addr->sa_family != AF_LINK || (it->ifa_flags & IFF_UP) == 0) {
                        continue;
                    }
                    if (ScopedFd tap = attach(it->ifa_name)) {
                        m_taps.push_back(std::move(tap));
                    } else {
                        ADD_FAILURE() << "could not tap " << it->ifa_name;
                    }
                }
            }

            [[nodiscard]] bool spotted(const Nonce &nonce, std::chrono::milliseconds timeout) const
            {
                std::vector<::pollfd> fds;
                for (const ScopedFd &tap : m_taps) {
                    fds.push_back({ tap.get(), POLLIN, 0 });
                }

                std::vector<std::byte> captured(TAP_BUFFER_SIZE);
                const auto deadline = std::chrono::steady_clock::now() + timeout;
                while (true) {
                    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now());
                    if (left.count() <= 0) {
                        return false;
                    }

                    const int ready = ::poll(fds.data(), fds.size(), static_cast<int>(left.count()));
                    if (ready < 0 && errno == EINTR) {
                        continue;
                    }
                    if (ready <= 0) {
                        return false;
                    }

                    for (const ::pollfd &fd : fds) {
                        if ((fd.revents & POLLIN) == 0) {
                            continue;
                        }
                        const ssize_t size = ::read(fd.fd, captured.data(), captured.size());
                        if (size > 0
                            && !std::ranges::search(std::span(captured.data(), static_cast<std::size_t>(size)), nonce)
                                        .empty()) {
                            return true;
                        }
                    }
                }
            }

        private:
            static ScopedFd attach(const char *ifName)
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
                    std::strncpy(request.ifr_name, ifName, sizeof(request.ifr_name) - 1);
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

            std::vector<ScopedFd> m_taps;
        };

        bool readNonce(int fd, const Nonce &nonce, std::chrono::milliseconds timeout)
        {
            std::array<std::byte, 2048> packet {};
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (true) {
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now());
                if (left.count() <= 0) {
                    return false;
                }

                ::pollfd ready { fd, POLLIN, 0 };
                const int events = ::poll(&ready, 1, static_cast<int>(left.count()));
                if (events < 0 && errno == EINTR) {
                    continue;
                }
                if (events <= 0) {
                    return false;
                }

                const ssize_t size = ::read(fd, packet.data(), packet.size());
                if (size > 0
                    && !std::ranges::search(std::span(packet.data(), static_cast<std::size_t>(size)), nonce).empty()) {
                    return true;
                }
            }
        }

        std::string anchorRules()
        {
            const auto rules = pf::pfctl({ "-a", ANCHOR, "-s", "rules" }, {});
            return rules ? rules.value() : std::string {};
        }

        int sendDatagram(const std::string &host, const Nonce &nonce)
        {
            const ConnectedSocket probe = udpConnect(host, PROBE_PORT);
            if (probe.error != 0) {
                return probe.error;
            }
            return ::send(probe.fd.get(), nonce.data(), nonce.size(), 0) < 0 ? errno : 0;
        }

        int sendAsForeignGroup(const std::string &host, const Nonce &nonce)
        {
            ::addrinfo hints {};
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

            ::addrinfo *resolved = nullptr;
            if (::getaddrinfo(host.c_str(), std::to_string(PROBE_PORT).c_str(), &hints, &resolved) != 0) {
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
            if (::waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) {
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
        if (sendDatagram(TEST_NET_V4, Nonce {}) != 0) {
            m_skipReason = "no uplink to probe through";
            return;
        }

        auto tun = createTun();
        if (!tun || !tun->first) {
            m_skipReason = "could not open a utun for the IPv6 test path";
            return;
        }
        if (tun->second == PROBE_IFACE) {
            m_skipReason = "the IPv6 test utun took the name the killswitch exempts";
            return;
        }

        const std::string dev = tun->second;
        m_ipv6TunFd = tun->first.release();
        const std::vector<std::string> setup {
            "ifconfig " + dev + " inet6 " + IPV6_PATH_ADDRESS + " alias",
            "ifconfig " + dev + " up",
            "route -q -n add -inet6 " + std::string(TEST_NET_V6_PREFIX) + " -interface " + dev,
        };
        if (!std::ranges::all_of(setup, sh)) {
            m_skipReason = "could not route the IPv6 test net into a utun";
            return;
        }

        m_ifName = PROBE_IFACE;
        pf::flushRules(ANCHOR);
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_skipReason.empty()) {
            pf::flushRules(ANCHOR);
        }
        if (m_ipv6TunFd >= 0) {
            ::close(m_ipv6TunFd);
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
        return count;
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const std::string &host, Bypass bypass) const
    {
        Nonce nonce {};
        ::arc4random_buf(nonce.data(), nonce.size());

        const bool ipv6 = host.find(':') != std::string::npos;
        std::optional<ProbeTap> tap;
        if (!ipv6) {
            tap.emplace();
        }

        const int error = bypass == Bypass::Proxy ? sendDatagram(host, nonce) : sendAsForeignGroup(host, nonce);
        if (error != 0) {
            ADD_FAILURE() << "could not send to " << host << ": " << std::strerror(error);
            return std::nullopt;
        }

        const bool delivered = ipv6 ? readNonce(m_ipv6TunFd, nonce, PROBE_TIMEOUT) : tap->spotted(nonce, PROBE_TIMEOUT);
        return delivered ? ProbeResult::Delivered : ProbeResult::Blocked;
    }

    using KillswitchMacos = KillswitchTest;

    TEST_F(KillswitchMacos, ConfiguredGroupIsExcluded)
    {
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_SOFT, static_cast<int>(::getegid()));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);

            expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "with the process's group");
            expectProbeResult(TEST_NET_V4, Bypass::None, ProbeResult::Blocked, "with the process's group");
        }
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_SOFT, static_cast<int>(FOREIGN_GID));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);

            expectProbeResult(TEST_NET_V4, Bypass::None, ProbeResult::Delivered, "with the foreign group");
            expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Blocked, "with the foreign group");
        }
    }
}
