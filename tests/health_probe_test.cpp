#include "health/control_probe.h"
#include "health/datagram_probe.h"
#include "health/dns_query.h"
#include "health/resolver_pool.h"
#include "net/ip.h"
#include "net/network_order.h"
#include "net/udp.h"
#include "util/random.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace
{

    using libxtun::RandomSource;
    using libxtun::health::ControlProbe;
    using libxtun::health::DatagramProbe;
    using libxtun::health::DnsQuery;
    using libxtun::health::DnsQueryFactory;
    using libxtun::health::DNS_PORT;
    using libxtun::health::EPHEMERAL_PORT_FIRST;
    using libxtun::health::EPHEMERAL_PORT_LAST;
    using libxtun::health::ProbeOutcome;
    using libxtun::health::ResolverPool;
    using libxtun::net::IpAddress;

    constexpr std::uint16_t RCODE_NO_ERROR = 0;
    constexpr std::uint16_t RCODE_NX_DOMAIN = 3;
    constexpr std::uint16_t RCODE_SERV_FAIL = 2;

    IpAddress addr(const char *text)
    {
        return IpAddress::parse(text).value_or(IpAddress {});
    }

    // QR = 0x8000, RD = 0x0100, RA = 0x0080
    constexpr std::uint16_t RECURSIVE_RESPONSE_FLAGS = 0x8180;

    std::vector<std::byte> responsePayload(const DnsQuery &query, std::uint16_t rcode)
    {
        std::vector<std::byte> out(query.bytes().begin(), query.bytes().end());
        libxtun::net::writeBigEndian16(out, 2, static_cast<std::uint16_t>(RECURSIVE_RESPONSE_FLAGS | rcode));
        return out;
    }

    std::vector<std::byte> reply(const DnsQuery &query, const IpAddress &from, const IpAddress &to, std::uint16_t rcode)
    {
        return libxtun::net::buildUdpDatagram(from, to, DNS_PORT, query.sourcePort(), responsePayload(query, rcode));
    }

    ResolverPool fullTunnelPool()
    {
        const std::vector<std::string> dns = { "1.1.1.1" };
        const std::vector<std::string> addresses = { "10.8.0.2/24" };
        const std::vector<std::string> routes = { "0.0.0.0/0" };
        return ResolverPool(dns, addresses, routes);
    }

    ResolverPool unroutedPool()
    {
        const std::vector<std::string> dns = { "1.1.1.1" };
        const std::vector<std::string> addresses = { "10.8.0.2/24" };
        const std::vector<std::string> routes = { "10.8.0.0/24" };
        return ResolverPool(dns, addresses, routes);
    }

} // namespace

TEST(HealthDnsQuery, IsAWellFormedStandardQuery)
{
    const DnsQuery query(0x1234, 0xdeadbeef, 51000);
    const auto bytes = query.bytes();

    ASSERT_GT(bytes.size(), 12u);
    EXPECT_EQ(libxtun::net::readBigEndian16(bytes, 0), 0x1234);
    EXPECT_EQ(libxtun::net::readBigEndian16(bytes, 2), 0x0100) << "recursion desired was not set";
    EXPECT_EQ(libxtun::net::readBigEndian16(bytes, 4), 1) << "qdcount was not 1";
    EXPECT_EQ(libxtun::net::readBigEndian16(bytes, 6), 0);
    EXPECT_EQ(std::to_integer<unsigned>(bytes[12]), 8u) << "the nonce label was not 8 bytes";
    EXPECT_EQ(query.sourcePort(), 51000);

    const auto type = libxtun::net::readBigEndian16(bytes, bytes.size() - 4);
    const auto klass = libxtun::net::readBigEndian16(bytes, bytes.size() - 2);
    EXPECT_EQ(type, 1);
    EXPECT_EQ(klass, 1);
}

TEST(HealthDnsQuery, TheNonceLabelVariesWithTheNonce)
{
    const DnsQuery first(1, 0x00000000, 51000);
    const DnsQuery second(1, 0xffffffff, 51000);

    ASSERT_EQ(first.bytes().size(), second.bytes().size());
    EXPECT_FALSE(std::equal(first.bytes().begin(), first.bytes().end(), second.bytes().begin()));
}

TEST(HealthDnsQuery, AcceptsNoErrorAndNxDomain)
{
    const DnsQuery query(0x4321, 0x11223344, 51000);

    EXPECT_TRUE(query.matchesResponse(responsePayload(query, RCODE_NO_ERROR)));
    EXPECT_TRUE(query.matchesResponse(responsePayload(query, RCODE_NX_DOMAIN)))
            << "NXDOMAIN proves the resolver did upstream work and must count";
}

TEST(HealthDnsQuery, RejectsAnythingThatIsNotTheAnswer)
{
    const DnsQuery query(0x4321, 0x11223344, 51000);
    const DnsQuery sameIdOtherName(0x4321, 0x55667788, 51000);

    auto wrongId = responsePayload(query, RCODE_NO_ERROR);
    libxtun::net::writeBigEndian16(wrongId, 0, 0x4322);
    EXPECT_FALSE(query.matchesResponse(wrongId));

    EXPECT_FALSE(query.matchesResponse(responsePayload(sameIdOtherName, RCODE_NO_ERROR)))
            << "an answer carrying our transaction id but a different question matched";

    EXPECT_FALSE(query.matchesResponse(responsePayload(query, RCODE_SERV_FAIL)));

    EXPECT_FALSE(query.matchesResponse(query.bytes())) << "the query itself matched as a response";

    auto truncated = responsePayload(query, RCODE_NO_ERROR);
    truncated.resize(truncated.size() - 2);
    EXPECT_FALSE(query.matchesResponse(truncated));

    EXPECT_FALSE(query.matchesResponse({}));
}

TEST(HealthDnsQuery, DefaultConstructedQueryMatchesNothing)
{
    const DnsQuery unset;
    const DnsQuery real(0x4321, 0x11223344, 51000);

    EXPECT_TRUE(unset.bytes().empty());
    EXPECT_FALSE(unset.matchesResponse(responsePayload(real, RCODE_NO_ERROR)));
    EXPECT_FALSE(unset.matchesResponse({}));
}

TEST(HealthDnsQuery, TheFactoryVariesEveryIdentifier)
{
    RandomSource random(1234);
    DnsQueryFactory factory(random);

    const DnsQuery first = factory.next();
    const DnsQuery second = factory.next();
    const DnsQuery third = factory.next();

    EXPECT_NE(first.sourcePort(), second.sourcePort());
    EXPECT_NE(second.sourcePort(), third.sourcePort());
    for (const DnsQuery *query : { &first, &second, &third }) {
        EXPECT_GE(query->sourcePort(), EPHEMERAL_PORT_FIRST);
        EXPECT_LE(query->sourcePort(), EPHEMERAL_PORT_LAST);
    }

    EXPECT_FALSE(std::equal(first.bytes().begin(), first.bytes().end(), second.bytes().begin()))
            << "two probes shared a transaction id and nonce";
}

TEST(HealthDatagramProbe, NoInTunnelTargetIsNoEvidence)
{
    const auto resolvers = unroutedPool();
    DatagramProbe probe(resolvers, [] { });

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)), ProbeOutcome::NotRun);
}

TEST(HealthDatagramProbe, StagesTheDatagramAndStealsTheReply)
{
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    std::vector<std::byte> staged;
    bool consumed = false;
    wake = [&] {
        std::array<std::byte, 2048> buf {};
        const int n = probe.stage(buf);
        ASSERT_GT(n, 0);
        staged.assign(buf.begin(), buf.begin() + n);
        consumed = probe.capture(reply(query, addr("1.1.1.1"), addr("10.8.0.2"), RCODE_NO_ERROR));
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::Answered);
    EXPECT_TRUE(consumed) << "the reply was not consumed, so the tun would see it twice";

    const auto sent = libxtun::net::UdpDatagramView::parse(staged);
    ASSERT_TRUE(sent.has_value());
    EXPECT_EQ(sent->source(), addr("10.8.0.2"));
    EXPECT_EQ(sent->destination(), addr("1.1.1.1"));
    EXPECT_EQ(sent->sourcePort(), query.sourcePort());
    EXPECT_EQ(sent->destinationPort(), DNS_PORT);
}

TEST(HealthDatagramProbe, StagesTheDatagramOnlyOnce)
{
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    int secondAttempt = -1;
    wake = [&] {
        std::array<std::byte, 2048> buf {};
        ASSERT_GT(probe.stage(buf), 0);
        secondAttempt = probe.stage(buf);
        probe.abort();
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_EQ(secondAttempt, 0) << "the probe datagram was staged twice";
}

TEST(HealthDatagramProbe, ForeignTrafficIsForwardedNotStolen)
{
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);
    const DnsQuery other(0x4444, 0x55556666, 51001);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    bool stoleWrongPort = false;
    bool stoleWrongSource = false;
    bool stoleWrongDestination = false;
    wake = [&] {
        std::array<std::byte, 2048> buf {};
        ASSERT_GT(probe.stage(buf), 0);

        stoleWrongPort = probe.capture(reply(other, addr("1.1.1.1"), addr("10.8.0.2"), RCODE_NO_ERROR));
        stoleWrongSource = probe.capture(reply(query, addr("8.8.8.8"), addr("10.8.0.2"), RCODE_NO_ERROR));
        stoleWrongDestination = probe.capture(reply(query, addr("1.1.1.1"), addr("10.8.0.9"), RCODE_NO_ERROR));
        probe.abort();
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_FALSE(stoleWrongPort) << "a reply addressed to another port was stolen";
    EXPECT_FALSE(stoleWrongSource) << "a reply from another resolver was stolen";
    EXPECT_FALSE(stoleWrongDestination) << "a reply to another host was stolen";
}

TEST(HealthDatagramProbe, NothingIsStolenWhileNoProbeIsInFlight)
{
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);
    DatagramProbe probe(resolvers, [] { });

    EXPECT_FALSE(probe.capture(reply(query, addr("1.1.1.1"), addr("10.8.0.2"), RCODE_NO_ERROR)));
}

TEST(HealthDatagramProbe, ThePreviousProbesReplyIsNotStolenAfterThePortRotates)
{
    const auto resolvers = fullTunnelPool();
    const DnsQuery first(0x1111, 0x22223333, 51000);
    const DnsQuery second(0x7777, 0x88889999, 51002);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    wake = [&] {
        std::array<std::byte, 2048> buf {};
        ASSERT_GT(probe.stage(buf), 0);
        ASSERT_TRUE(probe.capture(reply(first, addr("1.1.1.1"), addr("10.8.0.2"), RCODE_NO_ERROR)));
    };
    ASSERT_EQ(probe.run(first, std::chrono::milliseconds(500)), ProbeOutcome::Answered);

    bool stoleStale = false;
    wake = [&] {
        std::array<std::byte, 2048> buf {};
        ASSERT_GT(probe.stage(buf), 0);
        stoleStale = probe.capture(reply(first, addr("1.1.1.1"), addr("10.8.0.2"), RCODE_NO_ERROR));
        probe.abort();
    };

    EXPECT_EQ(probe.run(second, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_FALSE(stoleStale) << "a reply carrying the previous probe's port was stolen";
}

TEST(HealthDatagramProbe, SilentTunnelIsAFailure)
{
    const auto resolvers = fullTunnelPool();
    DatagramProbe probe(resolvers, [] { });

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)), ProbeOutcome::Failed);
}

TEST(HealthControlProbe, NoBindSocketIsNoEvidence)
{
    const auto resolvers = fullTunnelPool();
    ControlProbe probe(ControlProbe::BindSocket {}, resolvers);

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)), ProbeOutcome::NotRun)
            << "with no way to protect the socket the probe must not fabricate a verdict";
}

TEST(HealthControlProbe, TheDescriptorIsOfferedBeforeAnyTrafficLeavesIt)
{
    const auto resolvers = fullTunnelPool();

    int offeredFd = -1;
    int offeredFamily = 0;
    ControlProbe probe(
            [&](int fd, int family) {
                offeredFd = fd;
                offeredFamily = family;
            },
            resolvers);

    const auto outcome = probe.run(DnsQuery(0x1234, 0x5678, 51000), std::chrono::milliseconds(10));

    EXPECT_NE(outcome, ProbeOutcome::NotRun);
    EXPECT_GE(offeredFd, 0) << "the socket was never offered for protection";
    EXPECT_EQ(offeredFamily, AF_INET);
}
