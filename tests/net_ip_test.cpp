#include "net/ip.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace
{

    using libxtun::net::IpAddress;
    using libxtun::net::IpPrefix;
    using libxtun::net::PrefixSet;
    using libxtun::net::SockAddr;

    IpAddress addr(const char *text)
    {
        const auto parsed = IpAddress::parse(text);
        return parsed.value_or(IpAddress {});
    }

} // namespace

TEST(NetIp, ParsesAndFormatsBothFamilies)
{
    const auto v4 = IpAddress::parse("10.9.9.1");
    ASSERT_TRUE(v4.has_value());
    EXPECT_EQ(v4->family(), AF_INET);
    EXPECT_EQ(v4->octets().size(), 4u);
    EXPECT_EQ(v4->toString(), "10.9.9.1");

    const auto v6 = IpAddress::parse("2001:db8::1");
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(v6->family(), AF_INET6);
    EXPECT_EQ(v6->octets().size(), 16u);
    EXPECT_EQ(v6->toString(), "2001:db8::1");
}

TEST(NetIp, RejectsGarbage)
{
    EXPECT_FALSE(IpAddress::parse("").has_value());
    EXPECT_FALSE(IpAddress::parse("10.9.9").has_value());
    EXPECT_FALSE(IpAddress::parse("10.9.9.256").has_value());
    EXPECT_FALSE(IpAddress::parse("not-an-address").has_value());
    EXPECT_FALSE(IpAddress::parse("2001:db8::/32").has_value());
}

TEST(NetIp, DefaultConstructedIsInvalid)
{
    const IpAddress unset;

    EXPECT_FALSE(unset.valid());
    EXPECT_EQ(unset.family(), AF_UNSPEC);
    EXPECT_TRUE(unset.octets().empty());
    EXPECT_TRUE(unset.toString().empty());
    EXPECT_FALSE(unset.globallyRoutable());
}

TEST(NetIp, EqualityIgnoresUnusedOctets)
{
    EXPECT_EQ(addr("1.1.1.1"), addr("1.1.1.1"));
    EXPECT_NE(addr("1.1.1.1"), addr("1.1.1.2"));
    EXPECT_NE(addr("::1"), addr("1.1.1.1"));
}

TEST(NetIp, GlobalRoutabilityRejectsPrivateSpace)
{
    EXPECT_TRUE(addr("1.1.1.1").globallyRoutable());
    EXPECT_TRUE(addr("8.8.8.8").globallyRoutable());
    EXPECT_TRUE(addr("203.0.113.7").globallyRoutable());
    EXPECT_FALSE(addr("0.0.0.0").globallyRoutable());
    EXPECT_FALSE(addr("127.0.0.1").globallyRoutable());
    EXPECT_FALSE(addr("10.8.0.1").globallyRoutable());
    EXPECT_FALSE(addr("172.16.0.1").globallyRoutable());
    EXPECT_FALSE(addr("172.29.172.254").globallyRoutable());
    EXPECT_TRUE(addr("172.32.0.1").globallyRoutable());
    EXPECT_FALSE(addr("192.168.1.1").globallyRoutable());
    EXPECT_FALSE(addr("169.254.1.1").globallyRoutable());
    EXPECT_FALSE(addr("100.64.0.1").globallyRoutable());
    EXPECT_FALSE(addr("224.0.0.1").globallyRoutable());
}

TEST(NetIp, GlobalRoutabilityRejectsPrivateV6)
{
    EXPECT_TRUE(addr("2001:4860:4860::8888").globallyRoutable());
    EXPECT_TRUE(addr("2606:4700:4700::1111").globallyRoutable());

    EXPECT_FALSE(addr("::").globallyRoutable());
    EXPECT_FALSE(addr("::1").globallyRoutable());
    EXPECT_FALSE(addr("fe80::1").globallyRoutable());
    EXPECT_FALSE(addr("fc00::1").globallyRoutable());
    EXPECT_FALSE(addr("fd12:3456::1").globallyRoutable());
    EXPECT_FALSE(addr("ff02::1").globallyRoutable());
    EXPECT_FALSE(addr("::ffff:8.8.8.8").globallyRoutable());
}

TEST(NetIp, PrefixParsesAndContains)
{
    const auto prefix = IpPrefix::parse("10.8.0.0/24");
    ASSERT_TRUE(prefix.has_value());
    EXPECT_EQ(prefix->bits(), 24u);
    EXPECT_FALSE(prefix->isDefaultRoute());

    EXPECT_TRUE(prefix->contains(addr("10.8.0.1")));
    EXPECT_TRUE(prefix->contains(addr("10.8.0.255")));
    EXPECT_FALSE(prefix->contains(addr("10.8.1.1")));
    EXPECT_FALSE(prefix->contains(addr("2001:db8::1"))) << "a v6 address matched a v4 prefix";
}

TEST(NetIp, PrefixHandlesNonByteBoundaries)
{
    const auto cgnat = IpPrefix::parse("100.64.0.0/10");
    ASSERT_TRUE(cgnat.has_value());

    EXPECT_TRUE(cgnat->contains(addr("100.64.0.1")));
    EXPECT_TRUE(cgnat->contains(addr("100.127.255.255")));
    EXPECT_FALSE(cgnat->contains(addr("100.128.0.1")));
    EXPECT_FALSE(cgnat->contains(addr("100.63.255.255")));
}

TEST(NetIp, BareAddressIsAHostPrefix)
{
    const auto host = IpPrefix::parse("10.8.0.1");
    ASSERT_TRUE(host.has_value());
    EXPECT_EQ(host->bits(), 32u);
    EXPECT_TRUE(host->contains(addr("10.8.0.1")));
    EXPECT_FALSE(host->contains(addr("10.8.0.2")));

    const auto host6 = IpPrefix::parse("2001:db8::1");
    ASSERT_TRUE(host6.has_value());
    EXPECT_EQ(host6->bits(), 128u);
}

TEST(NetIp, PrefixRejectsBadCidr)
{
    EXPECT_FALSE(IpPrefix::parse("10.8.0.0/33").has_value());
    EXPECT_FALSE(IpPrefix::parse("2001:db8::/129").has_value());
    EXPECT_FALSE(IpPrefix::parse("10.8.0.0/").has_value());
    EXPECT_FALSE(IpPrefix::parse("10.8.0.0/24x").has_value());
    EXPECT_FALSE(IpPrefix::parse("10.8.0.0/-1").has_value());
    EXPECT_FALSE(IpPrefix::parse("nonsense/24").has_value());
}

TEST(NetIp, DefaultRouteIsRecognisedPerFamily)
{
    const auto v4 = IpPrefix::parse("0.0.0.0/0");
    const auto v6 = IpPrefix::parse("::/0");
    ASSERT_TRUE(v4.has_value());
    ASSERT_TRUE(v6.has_value());

    EXPECT_TRUE(v4->isDefaultRoute());
    EXPECT_TRUE(v6->isDefaultRoute());
    EXPECT_TRUE(v4->contains(addr("8.8.8.8")));
    EXPECT_FALSE(v4->contains(addr("2001:db8::1")));
    EXPECT_TRUE(v6->contains(addr("2001:db8::1")));
}

TEST(NetIp, PrefixSetSkipsUnparsableEntriesInsteadOfFailing)
{
    const std::vector<std::string> routes = { "10.8.0.0/24", "garbage", "2001:db8::/32", "10.8.0.0/99" };
    const PrefixSet set = PrefixSet::parseAll(routes);

    EXPECT_FALSE(set.empty());
    EXPECT_TRUE(set.contains(addr("10.8.0.7")));
    EXPECT_TRUE(set.contains(addr("2001:db8::5")));
    EXPECT_FALSE(set.contains(addr("1.1.1.1")));
}

TEST(NetIp, PrefixSetAnswersDefaultRoutePerFamily)
{
    const std::vector<std::string> split = { "10.8.0.0/24", "192.168.9.0/24" };
    EXPECT_FALSE(PrefixSet::parseAll(split).hasDefaultRoute(AF_INET));

    const std::vector<std::string> fullV4 = { "0.0.0.0/0" };
    const PrefixSet set = PrefixSet::parseAll(fullV4);
    EXPECT_TRUE(set.hasDefaultRoute(AF_INET));
    EXPECT_FALSE(set.hasDefaultRoute(AF_INET6)) << "a v4 default answered for v6";

    const std::vector<std::string> dual = { "0.0.0.0/0", "::/0" };
    const PrefixSet both = PrefixSet::parseAll(dual);
    EXPECT_TRUE(both.hasDefaultRoute(AF_INET));
    EXPECT_TRUE(both.hasDefaultRoute(AF_INET6));
}

TEST(NetIp, EmptyPrefixSetContainsNothing)
{
    const PrefixSet set;

    EXPECT_TRUE(set.empty());
    EXPECT_FALSE(set.contains(addr("1.1.1.1")));
    EXPECT_FALSE(set.hasDefaultRoute(AF_INET));
}

TEST(NetIp, SockAddrCarriesPortInNetworkOrder)
{
    const SockAddr v4(addr("1.1.1.1"), 53);
    ASSERT_EQ(v4.size(), sizeof(sockaddr_in));
    const auto *in4 = reinterpret_cast<const sockaddr_in *>(v4.data());
    EXPECT_EQ(in4->sin_family, AF_INET);
    EXPECT_EQ(ntohs(in4->sin_port), 53);

    const SockAddr v6(addr("2001:db8::1"), 5353);
    ASSERT_EQ(v6.size(), sizeof(sockaddr_in6));
    const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(v6.data());
    EXPECT_EQ(in6->sin6_family, AF_INET6);
    EXPECT_EQ(ntohs(in6->sin6_port), 5353);
}
