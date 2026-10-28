#include "health/dns_query.h"
#include "net/dns.h"
#include "net/ip.h"
#include "util/guaranteed.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <stdexcept>
#include <vector>

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

TEST(NetDns, HeaderFieldsSetProperly)
{
    std::array<std::byte, net::DnsRef::HEADER_LEN> buf {};
    net::DnsRef(buf).setId(0x1234).setFlags(0x8180).setQuestions(1).setAnswers(2).setAuthorities(3).setAdditionals(4);

    constexpr auto expected = makeBytes(0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04);
    EXPECT_TRUE(std::ranges::equal(buf, expected));

    const net::DnsView view(buf);
    EXPECT_EQ(view.id(), 0x1234);
    EXPECT_EQ(view.flags(), 0x8180);
    EXPECT_EQ(view.questions(), 1);
    EXPECT_EQ(view.answers(), 2);
    EXPECT_EQ(view.authorities(), 3);
    EXPECT_EQ(view.additionals(), 4);
}

TEST(NetDns, ParsesProbeQuery)
{
    const health::DnsQuery query(0x1234, 0xdeadbeef);

    const net::DnsView header(query.bytes().first<net::DnsView::HEADER_LEN>());
    EXPECT_EQ(header.id(), 0x1234);
    EXPECT_EQ(header.flags() & net::DnsFlag::RESPONSE, 0);
    EXPECT_EQ(header.questions(), 1);

    const auto question = test::guaranteed(net::DnsQuestion::parse(query.bytes()));
    EXPECT_EQ(question.type, net::DnsType::A);
    EXPECT_EQ(question.end, query.bytes().size());
}

TEST(NetDns, RejectsTruncatedQuestion)
{
    const health::DnsQuery query(0x1234, 0xdeadbeef);

    for (std::size_t len = 0; len < query.bytes().size(); ++len) {
        EXPECT_FALSE(net::DnsQuestion::parse(query.bytes().first(len))) << "accepted a query cut to " << len << " bytes";
    }
}

TEST(NetDns, DnsARecordAppendableToMessage)
{
    const health::DnsQuery query(0x1234, 0xdeadbeef);
    std::vector<std::byte> message(query.bytes().begin(), query.bytes().end());

    net::DnsARecord { 0x01020304, addr("192.0.2.77") }.appendTo(message);

    constexpr auto expected = makeBytes(0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x04, 0xc0,
                                        0x00, 0x02, 0x4d);
    EXPECT_TRUE(std::ranges::equal(std::span(message).subspan(query.bytes().size()), expected));
}
