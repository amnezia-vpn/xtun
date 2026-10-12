#include "net/icmp.h"
#include "net/ip.h"
#include "net/packet_builder.h"
#include "util/guaranteed.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <gtest/gtest.h>
#include <span>

using namespace libxtun;
using namespace libxtun;

namespace
{
    net::IpAddress addr(const char *text)
    {
        return test::guaranteed(net::IpAddress::parse(text));
    }

    template<typename... T> consteval auto makeBytes(T... vs)
    {
        ((vs < 0 || vs > 0xFF ? throw std::out_of_range("byte out of range") : void()), ...);
        return std::array<std::byte, sizeof...(T)> { static_cast<std::byte>(vs)... };
    }
}

TEST(NetPacketBuilder, CreatesValidIcmp)
{
    // clang-format off
    const auto expected = makeBytes(
        // IPv4 bytes
        0x45, 0x00, 0x00, 0x20,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x01, 0x54, 0xa7,
        0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
        // ICMP echo bytes
        0x08, 0x00, 0x6d, 0x60,
        0xab, 0xcd, 0x00, 0x01,
        // Payload - "ping" bytes
        0x70, 0x69, 0x6e, 0x67
    );
    // clang-format on

    std::array<std::byte, 1500> buf {};

    auto packet =
            test::guaranteed(net::PacketBuilder(buf)
                                     .ip(addr("10.0.0.1"), addr("10.0.0.2"))
                                     .withHeader([](net::IpRef &h) { h.setIdentification(0x1234); })
                                     .icmpEchoRequest()
                                     .withHeader([](net::IcmpEchoRef h) { h.setIdentifier(0xabcd).setSeqNumber(1); })
                                     .withPayload([](std::span<std::byte> s) -> std::size_t {
                                         std::memcpy(s.data(), "ping", s.size());
                                         return 4;
                                     })
                                     .finish());

    EXPECT_TRUE(std::ranges::equal(packet, expected));
}

TEST(NetPacketBuilder, CreatesValidUdp)
{
    // clang-format off
    const auto expected = makeBytes(
        // IPv4 bytes
        0x45, 0x00, 0x00, 0x20,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x54, 0x97,
        0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
        // UDP bytes: sport 12345, dport 53
        0x30, 0x39, 0x00, 0x35,
        0x00, 0x0c, 0xdc, 0x94,
        // Payload - "ping" bytes
        0x70, 0x69, 0x6e, 0x67
    );
    // clang-format on

    std::array<std::byte, 1500> buf {};

    auto packet = test::guaranteed(net::PacketBuilder(buf)
                                           .ip(addr("10.0.0.1"), addr("10.0.0.2"))
                                           .withHeader([](net::IpRef &h) { h.setIdentification(0x1234); })
                                           .udp(12345, 53)
                                           .withPayload([](std::span<std::byte> s) {
                                               std::memcpy(s.data(), "ping", 4);
                                               return 4;
                                           })
                                           .finish());

    EXPECT_TRUE(std::ranges::equal(packet, expected));
}

TEST(NetPacketBuilder, CreatesValidIcmp6)
{
    // clang-format off
    const auto expected = makeBytes(
        // IPv6 bytes
        0x60, 0x01, 0x23, 0x45,
        0x00, 0x0c, 0x3a, 0x40,
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // ICMPv6 echo request bytes
        0x80, 0x00, 0xfb, 0x14,
        0xab, 0xcd, 0x00, 0x01,
        // Payload - "ping" bytes
        0x70, 0x69, 0x6e, 0x67
    );
    // clang-format on

    std::array<std::byte, 1500> buf {};

    auto packet =
            test::guaranteed(net::PacketBuilder(buf)
                                     .ip6(addr("fd00::1"), addr("fd00::2"))
                                     .withHeader([](net::Ip6Ref &h) { h.setFlowLabel(0x12345); })
                                     .icmpEchoRequest()
                                     .withHeader([](net::Icmp6EchoRef &h) { h.setIdentifier(0xabcd).setSeqNumber(1); })
                                     .withPayload([](std::span<std::byte> s) -> std::size_t {
                                         std::memcpy(s.data(), "ping", 4);
                                         return 4;
                                     })
                                     .finish());

    EXPECT_TRUE(std::ranges::equal(packet, expected));
}

TEST(NetPacketBuilder, CreatesValidUdp6)
{
    // clang-format off
    const auto expected = makeBytes(
        // IPv6 bytes
        0x60, 0x01, 0x23, 0x45,
        0x00, 0x0c, 0x11, 0x40,
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // UDP bytes
        0x30, 0x39, 0x00, 0x35,
        0x00, 0x0c, 0xf6, 0x92,
        // Payload - "ping" bytes
        0x70, 0x69, 0x6e, 0x67
    );
    // clang-format on

    std::array<std::byte, 1500> buf {};

    auto packet = test::guaranteed(net::PacketBuilder(buf)
                                           .ip6(addr("fd00::1"), addr("fd00::2"))
                                           .withHeader([](net::Ip6Ref &h) { h.setFlowLabel(0x12345); })
                                           .udp(12345, 53)
                                           .withPayload([](std::span<std::byte> s) -> std::size_t {
                                               std::memcpy(s.data(), "ping", 4);
                                               return 4;
                                           })
                                           .finish());

    EXPECT_TRUE(std::ranges::equal(packet, expected));
}
