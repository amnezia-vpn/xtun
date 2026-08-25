#include "net/ip.h"
#include "net/udp.h"
#include "net/network_order.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace {

using libxtun::net::buildUdpDatagram;
using libxtun::net::internetChecksum;
using libxtun::net::IpAddress;
using libxtun::net::kIpv4HeaderLen;
using libxtun::net::kIpv6HeaderLen;
using libxtun::net::UdpDatagramView;

IpAddress addr(const char *text) {
    return IpAddress::parse(text).value_or(IpAddress{});
}

std::vector<std::byte> bytesOf(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

}  // namespace

TEST(NetUdp, ChecksumMatchesRfc1071Example) {
    const std::array<std::byte, 8> data{std::byte{0x00}, std::byte{0x01}, std::byte{0xf2},
                                        std::byte{0x03}, std::byte{0xf4}, std::byte{0xf5},
                                        std::byte{0xf6}, std::byte{0xf7}};

    EXPECT_EQ(internetChecksum(data), 0x220d);
}

TEST(NetUdp, ChecksumOfAValidatedHeaderIsZero) {
    const auto payload = bytesOf("probe");
    const auto packet = buildUdpDatagram(addr("10.9.9.1"), addr("1.1.1.1"), 51000, 53, payload);
    ASSERT_FALSE(packet.empty());

    EXPECT_EQ(internetChecksum({packet.data(), kIpv4HeaderLen}), 0)
        << "the receiver-side check over the IPv4 header did not cancel out";
}

TEST(NetUdp, V4RoundTrip) {
    const auto payload = bytesOf("xtun-probe");
    const auto packet = buildUdpDatagram(addr("10.9.9.1"), addr("1.1.1.1"), 51000, 53, payload);
    ASSERT_EQ(packet.size(), kIpv4HeaderLen + 8 + payload.size());

    const auto view = UdpDatagramView::parse(packet);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->sourcePort(), 51000);
    EXPECT_EQ(view->destinationPort(), 53);
    EXPECT_EQ(view->source(), addr("10.9.9.1"));
    EXPECT_EQ(view->destination(), addr("1.1.1.1"));
    ASSERT_EQ(view->payload().size(), payload.size());
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), view->payload().begin()));
}

TEST(NetUdp, V6RoundTrip) {
    const auto payload = bytesOf("xtun-probe-v6");
    const auto packet =
        buildUdpDatagram(addr("2001:db8::2"), addr("2606:4700:4700::1111"), 49999, 53, payload);
    ASSERT_EQ(packet.size(), kIpv6HeaderLen + 8 + payload.size());

    const auto view = UdpDatagramView::parse(packet);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->sourcePort(), 49999);
    EXPECT_EQ(view->destinationPort(), 53);
    EXPECT_EQ(view->source(), addr("2001:db8::2"));
    EXPECT_EQ(view->destination(), addr("2606:4700:4700::1111"));
    ASSERT_EQ(view->payload().size(), payload.size());
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), view->payload().begin()));
}

TEST(NetUdp, TheViewBorrowsRatherThanCopies) {
    const auto payload = bytesOf("borrowed");
    auto packet = buildUdpDatagram(addr("10.9.9.1"), addr("1.1.1.1"), 51000, 53, payload);

    const auto view = UdpDatagramView::parse(packet);
    ASSERT_TRUE(view.has_value());
    ASSERT_EQ(view->sourcePort(), 51000);

    libxtun::net::writeBigEndian16(packet, kIpv4HeaderLen, 51001);

    EXPECT_EQ(view->sourcePort(), 51001) << "the view decoded a copy, not the caller's buffer";
}

TEST(NetUdp, MismatchedOrInvalidFamiliesBuildNothing) {
    const auto payload = bytesOf("x");

    EXPECT_TRUE(buildUdpDatagram(addr("10.9.9.1"), addr("2001:db8::1"), 1, 2, payload).empty());
    EXPECT_TRUE(buildUdpDatagram(IpAddress{}, addr("1.1.1.1"), 1, 2, payload).empty());
}

TEST(NetUdp, ParseRejectsMalformedPackets) {
    const auto payload = bytesOf("xtun");
    const auto packet = buildUdpDatagram(addr("10.9.9.1"), addr("1.1.1.1"), 51000, 53, payload);

    EXPECT_FALSE(UdpDatagramView::parse({}).has_value());

    auto truncated = packet;
    truncated.resize(kIpv4HeaderLen + 4);
    EXPECT_FALSE(UdpDatagramView::parse(truncated).has_value()) << "a truncated UDP header parsed";

    auto short_header = packet;
    short_header.resize(12);
    EXPECT_FALSE(UdpDatagramView::parse(short_header).has_value());

    auto not_udp = packet;
    not_udp[9] = static_cast<std::byte>(6);
    EXPECT_FALSE(UdpDatagramView::parse(not_udp).has_value()) << "TCP parsed as UDP";

    auto fragment = packet;
    libxtun::net::writeBigEndian16(fragment, 6, 0x2000);
    EXPECT_FALSE(UdpDatagramView::parse(fragment).has_value()) << "a fragment parsed";

    auto offset_fragment = packet;
    libxtun::net::writeBigEndian16(offset_fragment, 6, 0x0001);
    EXPECT_FALSE(UdpDatagramView::parse(offset_fragment).has_value());

    auto bad_version = packet;
    bad_version[0] = static_cast<std::byte>(0x55);
    EXPECT_FALSE(UdpDatagramView::parse(bad_version).has_value());

    auto lying_length = packet;
    libxtun::net::writeBigEndian16(lying_length, kIpv4HeaderLen + 4, 4000);
    EXPECT_FALSE(UdpDatagramView::parse(lying_length).has_value())
        << "a UDP length past the end of the buffer parsed";
}

TEST(NetUdp, ParseRejectsMalformedV6Packets) {
    const auto payload = bytesOf("xtun");
    const auto packet =
        buildUdpDatagram(addr("2001:db8::2"), addr("2001:db8::1"), 51000, 53, payload);

    auto truncated = packet;
    truncated.resize(kIpv6HeaderLen - 1);
    EXPECT_FALSE(UdpDatagramView::parse(truncated).has_value());

    auto not_udp = packet;
    not_udp[6] = static_cast<std::byte>(58);
    EXPECT_FALSE(UdpDatagramView::parse(not_udp).has_value()) << "ICMPv6 parsed as UDP";

    auto lying_length = packet;
    libxtun::net::writeBigEndian16(lying_length, 4, 4000);
    EXPECT_FALSE(UdpDatagramView::parse(lying_length).has_value());
}

TEST(NetUdp, EmptyPayloadIsAValidDatagram) {
    const auto packet = buildUdpDatagram(addr("10.9.9.1"), addr("1.1.1.1"), 51000, 53, {});
    ASSERT_EQ(packet.size(), kIpv4HeaderLen + 8);

    const auto view = UdpDatagramView::parse(packet);
    ASSERT_TRUE(view.has_value());
    EXPECT_TRUE(view->payload().empty());
    EXPECT_EQ(view->destinationPort(), 53);
}
