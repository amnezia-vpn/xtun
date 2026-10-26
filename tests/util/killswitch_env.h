#ifndef TEST_KILLSWITCH_ENV_H
#define TEST_KILLSWITCH_ENV_H

#include "killswitch.h"
#include "os.h"
#include "tun_device.h"
#include "util/noncopyable.h"
#include "xtun.h"

#if !defined(_WIN32)
    #include <ifaddrs.h>
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

namespace libxtun::test
{
    constexpr const char *FAKE_UPLINK_V4 = "10.10.0.2/24";
    constexpr const char *FAKE_UPLINK_V6 = "fd00:10::2/64";
    constexpr const char *LOOPBACK_V4 = "127.0.0.1";
    constexpr const char *PROBE_HOST = "example.com";
    constexpr std::uint16_t PROBE_PORT = 443;
    constexpr auto PROBE_TIMEOUT = std::chrono::milliseconds(500);
    constexpr auto PROBE_SLICE = std::chrono::milliseconds(10);
    constexpr int CONNECTED_VIA_TUNNEL = 200;
    constexpr int CONNECTED_ELSEWHERE = 201;

    const std::vector<std::string> PROBE_ADDRS = resolve(PROBE_HOST);

    static std::string probeAddress(std::size_t index)
    {
        return index < PROBE_ADDRS.size() ? PROBE_ADDRS[index] : std::string {};
    }

    struct Destination
    {
        const char *name;
        std::string host;
    };

    const Destination INTERNET_V4 { "internet v4", probeAddress(1) };
    const Destination INTERNET_V6 { "internet v6", "2001:db8::1" };
    const Destination LAN { "LAN", "10.10.0.5" };
    const Destination HIJACKED { "hijacked route", "198.51.100.1" };

    enum class Sender {
        App,
        Proxy
    };

    enum class ProbeResult {
        Tunnel,
        Uplink,
        Blocked
    };

    inline std::string localAddress(const ScopedFd &sock)
    {
        ::sockaddr_storage local {};
        ::socklen_t size = sizeof(local);
        std::array<char, INET6_ADDRSTRLEN> address {};
#if defined(_WIN32)
        const auto handle = static_cast<SOCKET>(sock.get());
#else
        const int handle = sock.get();
#endif
        if (::getsockname(handle, reinterpret_cast<::sockaddr *>(&local), &size) != 0
            || ::getnameinfo(reinterpret_cast<::sockaddr *>(&local), size, address.data(),
                             static_cast<::socklen_t>(address.size()), nullptr, 0, NI_NUMERICHOST)
                    != 0) {
            return {};
        }
        return address.data();
    }

#if !defined(_WIN32)
    inline std::string ifnameFromAddr(const char *address)
    {
        in_addr wanted {};
        ::ifaddrs *list = nullptr;
        if (::inet_pton(AF_INET, address, &wanted) != 1 || ::getifaddrs(&list) != 0) {
            return {};
        }

        std::string name;
        for (const ::ifaddrs *it = list; it != nullptr; it = it->ifa_next) {
            if (it->ifa_addr != nullptr && it->ifa_addr->sa_family == AF_INET
                && reinterpret_cast<const sockaddr_in *>(it->ifa_addr)->sin_addr.s_addr == wanted.s_addr) {
                name = it->ifa_name;
                break;
            }
        }
        ::freeifaddrs(list);
        return name;
    }
#endif

    inline std::ostream &operator<<(std::ostream &out, Sender sender)
    {
        switch (sender) {
        case Sender::App: return out << "from an app";
        case Sender::Proxy: return out << "from the proxy";
        }
        return out;
    }

    inline std::ostream &operator<<(std::ostream &out, ProbeResult result)
    {
        switch (result) {
        case ProbeResult::Tunnel: return out << "tunnel";
        case ProbeResult::Uplink: return out << "uplink";
        case ProbeResult::Blocked: return out << "blocked";
        }
        return out;
    }

    class KillswitchEnv : private NonCopyable
    {
    public:
        explicit KillswitchEnv(bool realEndpoint = false);
        ~KillswitchEnv();

        [[nodiscard]] std::string_view skipReason() const noexcept
        {
            return m_skipReason;
        }
        [[nodiscard]] std::unique_ptr<Killswitch> create(libxtun_killswitch_mode mode) const;
        [[nodiscard]] libxtun_error update(Killswitch &killswitch) const;
        [[nodiscard]] int ruleCount() const;
        [[nodiscard]] std::optional<ProbeResult> connect(const std::string &host, std::uint16_t port, Sender sender) const;
        [[nodiscard]] std::optional<ProbeResult> probe(const Destination &to, Sender sender) const;
        [[nodiscard]] bool removeTunnelRoutes(const std::vector<std::string> &routes) const;

    private:
        [[nodiscard]] std::vector<std::byte> handleUplinkPacket(std::span<const std::byte> packet) const;

        bool m_realEndpoint = false;
        std::string m_skipReason;
        int m_ifIndex = 0;
        std::string m_ifName;
        std::thread m_uplinkReader;
#if defined(__linux__)
        int m_netnsFd = -1;
        ScopedFd m_uplinkFd;
        std::atomic<bool> m_stopReader = false;
#elif defined(__APPLE__)
        ScopedFd m_uplinkFd;
        unsigned m_uplinkIfIndex = 0;
        std::string m_originalGateway;
        std::atomic<bool> m_stopReader = false;
#elif defined(_WIN32)
        std::unique_ptr<TunDevice> m_uplinkTun;
        unsigned m_uplinkIfIndex = 0;
#endif
    };

    class KillswitchTest : public testing::Test
    {
    protected:
        explicit KillswitchTest(bool realEndpoint = false) : m_env(realEndpoint)
        {
        }
        void SetUp() override
        {
            if (!m_env.skipReason().empty()) {
                GTEST_SKIP() << "skipped: " << m_env.skipReason();
            }
            ASSERT_GE(PROBE_ADDRS.size(), 2u) << "could not resolve two addresses of " << PROBE_HOST;
        }
        void expectProbeResult(const Destination &to, Sender sender, ProbeResult wanted, std::string_view phase = {})
        {
            if (const std::optional<ProbeResult> result = m_env.probe(to, sender)) {
                EXPECT_EQ(*result, wanted) << to.name << ", " << sender << ' ' << phase;
            }
        }
        [[nodiscard]] static bool persistent(libxtun_killswitch_mode mode) noexcept
        {
            return mode == LIBXTUN_KILLSWITCH_MODE_HARD;
        }
        KillswitchEnv m_env;
    };
}

#endif
