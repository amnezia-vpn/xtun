#ifndef TEST_KILLSWITCH_ENV_H
#define TEST_KILLSWITCH_ENV_H

#include "killswitch.h"
#include "net/ip.h"
#include "net/packet_builder.h"
#include "net/udp.h"
#include "os.h"
#include "tun_device.h"
#include "util/noncopyable.h"
#include "xtun.h"

#if !defined(_WIN32)
    #include <ifaddrs.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

namespace libxtun::test
{
    class MemTun;

    constexpr const char *TEST_NET_V4 = "203.0.113.1";
    constexpr const char *TEST_NET_V6 = "2001:db8::1";
    constexpr const char *TEST_NET_V6_PREFIX = "2001:db8::/32";
    constexpr const char *HIJACKED_PREFIX = "198.51.100.0/24";
    constexpr const char *LAN_PREFIX = "10.10.0.0/24";
    constexpr const char *FAKE_UPLINK_V4 = "10.10.0.2/24";
    constexpr const char *FAKE_UPLINK_V6 = "fd00:10::2/64";
    constexpr const char *CLIENT_SIDE_V4 = "10.20.0.1/24";
    constexpr const char *CLIENT_SIDE_PREFIX = "10.20.0.0/24";
    constexpr const char *FORWARDED_SOURCE = "10.20.0.2";
    constexpr const char *TUNNEL_ADDRESS = "10.9.10.2";
    constexpr const char *LOOPBACK_V4 = "127.0.0.1";
    constexpr std::uint16_t PROBE_PORT = 53;
    constexpr auto BLOCKED_TIMEOUT = std::chrono::milliseconds(500);
    constexpr auto DELIVERY_TIMEOUT = std::chrono::milliseconds(1500);
    constexpr auto PROBE_SLICE = std::chrono::milliseconds(10);

    using Nonce = std::array<std::byte, 16>;

    struct Destination
    {
        const char *name;
        const char *host;
        bool viaDefault;
    };

    constexpr Destination INTERNET_V4 { "internet v4", TEST_NET_V4, true };
    constexpr Destination INTERNET_V6 { "internet v6", TEST_NET_V6, false };
    constexpr Destination LAN { "LAN", "10.10.0.5", false };
    constexpr Destination HIJACKED { "hijacked route", "198.51.100.1", false };

    enum class Sender {
        App,
        Proxy,
        Forwarded
    };

    enum class SendResult {
        Out,
        Refused,
        Failed
    };

    enum class ProbeResult {
        Tunnel,
        Uplink,
        Blocked
    };

    inline Nonce randomNonce()
    {
        std::random_device device;
        Nonce nonce {};
        for (std::byte &octet : nonce) {
            octet = static_cast<std::byte>(device() & 0xffu);
        }
        return nonce;
    }

    inline bool containsNonce(std::span<const std::byte> data, const Nonce &nonce)
    {
        return !std::ranges::search(data, nonce).empty();
    }

    inline bool udpPktContainsNonce(std::span<const std::byte> packet, const Nonce &nonce)
    {
        if (packet.empty()) {
            return false;
        }

        std::size_t udpOffset = 0;
        switch (std::to_integer<unsigned>(packet[0]) >> 4) {
        case 4: {
            if (packet.size() < net::IpView::HEADER_LEN) {
                return false;
            }
            const net::IpView ip(packet.first<net::IpView::HEADER_LEN>());
            if (ip.protocol() != IPPROTO_UDP) {
                return false;
            }
            udpOffset = ip.ihlBytes();
            break;
        }
        case 6: {
            if (packet.size() < net::Ip6View::HEADER_LEN) {
                return false;
            }
            const net::Ip6View ip6(packet.first<net::Ip6View::HEADER_LEN>());
            if (ip6.nextHeader() != IPPROTO_UDP) {
                return false;
            }
            udpOffset = net::Ip6View::HEADER_LEN;
            break;
        }
        default: return false;
        }

        const std::size_t payloadOffset = udpOffset + net::UdpView::HEADER_LEN;
        return packet.size() > payloadOffset && containsNonce(packet.subspan(payloadOffset), nonce);
    }

    inline std::uint16_t fwdSrcPort(const Nonce &nonce)
    {
        const unsigned seed = std::to_integer<unsigned>(nonce[0]) * 256 + std::to_integer<unsigned>(nonce[1]);
        return static_cast<std::uint16_t>(40000 + seed % 20000);
    }

    inline std::vector<std::byte> forwardedPacket(const net::IpAddress &destination, std::uint16_t port,
                                                  const Nonce &nonce)
    {
        std::vector<std::byte> buffer(net::IpView::HEADER_LEN + net::UdpView::HEADER_LEN + nonce.size());
        const auto packet = net::PacketBuilder(buffer)
                                    .ip(*net::IpAddress::parse(FORWARDED_SOURCE), destination)
                                    .udp(fwdSrcPort(nonce), port)
                                    .withPayload([&](std::span<std::byte> space) -> std::optional<std::size_t> {
                                        std::ranges::copy(nonce, space.begin());
                                        return nonce.size();
                                    })
                                    .finish();
        buffer.resize(packet ? packet->size() : 0);
        return buffer;
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
        case Sender::Forwarded: return out << "forwarded";
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
        KillswitchEnv();
        ~KillswitchEnv();

        [[nodiscard]] std::string_view skipReason() const noexcept
        {
            return m_skipReason;
        }
        [[nodiscard]] std::unique_ptr<Killswitch> create(libxtun_killswitch_mode mode) const;
        [[nodiscard]] libxtun_error update(Killswitch &killswitch) const;
        [[nodiscard]] int ruleCount() const;
        [[nodiscard]] SendResult send(const std::string &host, std::uint16_t port, Sender sender,
                                     const Nonce &nonce) const;
        [[nodiscard]] std::optional<ProbeResult> probe(const Destination &to, Sender sender, ProbeResult expected,
                                                       MemTun *server = nullptr) const;
        [[nodiscard]] bool removeTunnelRoutes(const std::vector<std::string> &routes) const;

    private:
        [[nodiscard]] std::optional<ProbeResult> pollUplink(const Destination &to, const Nonce &nonce) const;

        std::string m_skipReason;
        int m_ifIndex = 0;
        std::string m_ifName;
#if defined(__linux__)
        int m_netnsFd = -1;
        ScopedFd m_uplinkFd;
        ScopedFd m_clientFd;
        bool m_forwarding = false;
#elif defined(__APPLE__)
        ScopedFd m_uplinkFd;
        ScopedFd m_clientFd;
        ScopedFd m_tap;
        unsigned m_defaultIfIndex = 0;
        bool m_restoreForwarding = false;
#elif defined(_WIN32)
        std::unique_ptr<TunDevice> m_uplinkTun;
        std::unique_ptr<TunDevice> m_clientTun;
        std::thread m_uplinkReader;
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_arrived;
        mutable std::deque<std::vector<std::byte>> m_uplinkPackets;
#endif
    };

    class KillswitchTest : public testing::Test
    {
    protected:
        void SetUp() override
        {
            if (!m_env.skipReason().empty()) {
                GTEST_SKIP() << "skipped: " << m_env.skipReason();
            }
        }
        void expectProbeResult(const Destination &to, Sender sender, ProbeResult wanted, std::string_view phase = {})
        {
            if (const std::optional<ProbeResult> result = m_env.probe(to, sender, wanted)) {
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
