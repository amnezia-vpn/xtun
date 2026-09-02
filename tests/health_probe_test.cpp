#include "health/control_probe.h"
#include "health/datagram_probe.h"
#include "health/dns_query.h"
#include "health/resolver_pool.h"
#include "net/ip.h"
#include "net/socket.h"
#include "net/udp.h"
#include "net/network_order.h"
#include "util/random.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

using libxtun::RandomSource;
using libxtun::health::ControlProbe;
using libxtun::health::DatagramProbe;
using libxtun::health::DnsQuery;
using libxtun::health::DnsQueryFactory;
using libxtun::health::kDnsPort;
using libxtun::health::kEphemeralPortFirst;
using libxtun::health::kEphemeralPortLast;
using libxtun::health::ProbeOutcome;
using libxtun::health::ResolverPool;
using libxtun::net::IpAddress;

constexpr std::uint16_t kRcodeNoError = 0;
constexpr std::uint16_t kRcodeNxDomain = 3;
constexpr std::uint16_t kRcodeServFail = 2;

IpAddress addr(const char *text) {
    return IpAddress::parse(text).value_or(IpAddress{});
}

// QR = 0x8000, RD = 0x0100, RA = 0x0080
constexpr std::uint16_t kRecursiveResponseFlags = 0x8180;

std::vector<std::byte> responsePayload(const DnsQuery &query, std::uint16_t rcode) {
    std::vector<std::byte> out(query.bytes().begin(), query.bytes().end());
    libxtun::net::writeBigEndian16(out, 2,
                                   static_cast<std::uint16_t>(kRecursiveResponseFlags | rcode));
    return out;
}

std::vector<std::byte> reply(const DnsQuery &query, const IpAddress &from, const IpAddress &to,
                             std::uint16_t rcode) {
    return libxtun::net::buildUdpDatagram(from, to, kDnsPort, query.sourcePort(),
                                          responsePayload(query, rcode));
}

ResolverPool fullTunnelPool() {
    const std::vector<std::string> dns = {"1.1.1.1"};
    const std::vector<std::string> addresses = {"10.8.0.2/24"};
    const std::vector<std::string> routes = {"0.0.0.0/0"};
    return ResolverPool(dns, addresses, routes);
}

ResolverPool unroutedPool() {
    const std::vector<std::string> dns = {"1.1.1.1"};
    const std::vector<std::string> addresses = {"10.8.0.2/24"};
    const std::vector<std::string> routes = {"10.8.0.0/24"};
    return ResolverPool(dns, addresses, routes);
}

class LoopbackResolver {
  public:
    LoopbackResolver() : m_socket(libxtun::net::Socket::udp(AF_INET)) {
        if (!m_socket) {
            return;
        }
        sockaddr_in wanted{};
        wanted.sin_family = AF_INET;
        ::inet_pton(AF_INET, "127.0.0.1", &wanted.sin_addr);
        socklen_t len = sizeof(m_bound);
        if (::bind(fd(), reinterpret_cast<sockaddr *>(&wanted), sizeof(wanted)) != 0 ||
            ::getsockname(fd(), reinterpret_cast<sockaddr *>(&m_bound), &len) != 0) {
            m_socket.reset();
        }
    }

    ~LoopbackResolver() {
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    bool ready() const { return m_socket.has_value(); }

    libxtun::net::SockAddr peer() const {
        return {addr("127.0.0.1"), ntohs(m_bound.sin_port)};
    }

    void answer(bool junk_first) {
        m_thread = std::thread([this, junk_first] { serve(junk_first); });
    }

  private:
    int fd() const { return libxtun::net::fromAbiDescriptor(m_socket->native()); }

    void serve(bool junk_first) {
        std::array<std::byte, libxtun::health::kMaxDnsResponse> buf{};
        sockaddr_in from{};
        socklen_t len = sizeof(from);
        const auto received =
            ::recvfrom(fd(), reinterpret_cast<char *>(buf.data()), static_cast<int>(buf.size()), 0,
                       reinterpret_cast<sockaddr *>(&from), &len);
        if (received <= 0) {
            return;
        }

        if (junk_first) {
            constexpr char noise[] = "not-an-answer";
            ::sendto(fd(), noise, static_cast<int>(sizeof(noise)), 0,
                     reinterpret_cast<sockaddr *>(&from), len);
        }

        std::vector<std::byte> answer(buf.begin(), buf.begin() + received);
        libxtun::net::writeBigEndian16(answer, 2, kRecursiveResponseFlags | kRcodeNoError);
        ::sendto(fd(), reinterpret_cast<const char *>(answer.data()),
                 static_cast<int>(answer.size()), 0, reinterpret_cast<sockaddr *>(&from), len);
    }

    std::optional<libxtun::net::Socket> m_socket;
    sockaddr_in m_bound{};
    std::thread m_thread;
};

}  // namespace

TEST(HealthDnsQuery, IsAWellFormedStandardQuery) {
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

TEST(HealthDnsQuery, TheNonceLabelVariesWithTheNonce) {
    const DnsQuery first(1, 0x00000000, 51000);
    const DnsQuery second(1, 0xffffffff, 51000);

    ASSERT_EQ(first.bytes().size(), second.bytes().size());
    EXPECT_FALSE(std::equal(first.bytes().begin(), first.bytes().end(), second.bytes().begin()));
}

TEST(HealthDnsQuery, AcceptsNoErrorAndNxDomain) {
    const DnsQuery query(0x4321, 0x11223344, 51000);

    EXPECT_TRUE(query.matchesResponse(responsePayload(query, kRcodeNoError)));
    EXPECT_TRUE(query.matchesResponse(responsePayload(query, kRcodeNxDomain)))
        << "NXDOMAIN proves the resolver did upstream work and must count";
}

TEST(HealthDnsQuery, RejectsAnythingThatIsNotTheAnswer) {
    const DnsQuery query(0x4321, 0x11223344, 51000);
    const DnsQuery same_id_other_name(0x4321, 0x55667788, 51000);

    auto wrong_id = responsePayload(query, kRcodeNoError);
    libxtun::net::writeBigEndian16(wrong_id, 0, 0x4322);
    EXPECT_FALSE(query.matchesResponse(wrong_id));

    EXPECT_FALSE(query.matchesResponse(responsePayload(same_id_other_name, kRcodeNoError)))
        << "an answer carrying our transaction id but a different question matched";

    EXPECT_FALSE(query.matchesResponse(responsePayload(query, kRcodeServFail)));

    EXPECT_FALSE(query.matchesResponse(query.bytes())) << "the query itself matched as a response";

    auto truncated = responsePayload(query, kRcodeNoError);
    truncated.resize(truncated.size() - 2);
    EXPECT_FALSE(query.matchesResponse(truncated));

    EXPECT_FALSE(query.matchesResponse({}));
}

TEST(HealthDnsQuery, DefaultConstructedQueryMatchesNothing) {
    const DnsQuery unset;
    const DnsQuery real(0x4321, 0x11223344, 51000);

    EXPECT_TRUE(unset.bytes().empty());
    EXPECT_FALSE(unset.matchesResponse(responsePayload(real, kRcodeNoError)));
    EXPECT_FALSE(unset.matchesResponse({}));
}

TEST(HealthDnsQuery, TheFactoryVariesEveryIdentifier) {
    RandomSource random(1234);
    DnsQueryFactory factory(random);

    const DnsQuery first = factory.next();
    const DnsQuery second = factory.next();
    const DnsQuery third = factory.next();

    EXPECT_NE(first.sourcePort(), second.sourcePort());
    EXPECT_NE(second.sourcePort(), third.sourcePort());
    for (const DnsQuery *query : {&first, &second, &third}) {
        EXPECT_GE(query->sourcePort(), kEphemeralPortFirst);
        EXPECT_LE(query->sourcePort(), kEphemeralPortLast);
    }

    EXPECT_FALSE(std::equal(first.bytes().begin(), first.bytes().end(), second.bytes().begin()))
        << "two probes shared a transaction id and nonce";
}

TEST(HealthDatagramProbe, NoInTunnelTargetIsNoEvidence) {
    const auto resolvers = unroutedPool();
    DatagramProbe probe(resolvers, [] {});

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)),
              ProbeOutcome::NotRun);
}

TEST(HealthDatagramProbe, StagesTheDatagramAndStealsTheReply) {
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    std::vector<std::byte> staged;
    bool consumed = false;
    wake = [&] {
        std::array<std::byte, 2048> buf{};
        const int n = probe.stage(buf);
        ASSERT_GT(n, 0);
        staged.assign(buf.begin(), buf.begin() + n);
        consumed = probe.capture(reply(query, addr("1.1.1.1"), addr("10.8.0.2"), kRcodeNoError));
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::Answered);
    EXPECT_TRUE(consumed) << "the reply was not consumed, so the tun would see it twice";

    const auto sent = libxtun::net::UdpDatagramView::parse(staged);
    ASSERT_TRUE(sent.has_value());
    EXPECT_EQ(sent->source(), addr("10.8.0.2"));
    EXPECT_EQ(sent->destination(), addr("1.1.1.1"));
    EXPECT_EQ(sent->sourcePort(), query.sourcePort());
    EXPECT_EQ(sent->destinationPort(), kDnsPort);
}

TEST(HealthDatagramProbe, StagesTheDatagramOnlyOnce) {
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    int second_attempt = -1;
    wake = [&] {
        std::array<std::byte, 2048> buf{};
        ASSERT_GT(probe.stage(buf), 0);
        second_attempt = probe.stage(buf);
        probe.abort();
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_EQ(second_attempt, 0) << "the probe datagram was staged twice";
}

TEST(HealthDatagramProbe, ForeignTrafficIsForwardedNotStolen) {
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);
    const DnsQuery other(0x4444, 0x55556666, 51001);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    bool stole_wrong_port = false;
    bool stole_wrong_source = false;
    bool stole_wrong_destination = false;
    wake = [&] {
        std::array<std::byte, 2048> buf{};
        ASSERT_GT(probe.stage(buf), 0);

        stole_wrong_port = probe.capture(reply(other, addr("1.1.1.1"), addr("10.8.0.2"),
                                              kRcodeNoError));
        stole_wrong_source = probe.capture(reply(query, addr("8.8.8.8"), addr("10.8.0.2"),
                                                kRcodeNoError));
        stole_wrong_destination = probe.capture(reply(query, addr("1.1.1.1"), addr("10.8.0.9"),
                                                     kRcodeNoError));
        probe.abort();
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_FALSE(stole_wrong_port) << "a reply addressed to another port was stolen";
    EXPECT_FALSE(stole_wrong_source) << "a reply from another resolver was stolen";
    EXPECT_FALSE(stole_wrong_destination) << "a reply to another host was stolen";
}

TEST(HealthDatagramProbe, NothingIsStolenWhileNoProbeIsInFlight) {
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);
    DatagramProbe probe(resolvers, [] {});

    EXPECT_FALSE(probe.capture(reply(query, addr("1.1.1.1"), addr("10.8.0.2"), kRcodeNoError)));
}

TEST(HealthDatagramProbe, ThePreviousProbesReplyIsNotStolenAfterThePortRotates) {
    const auto resolvers = fullTunnelPool();
    const DnsQuery first(0x1111, 0x22223333, 51000);
    const DnsQuery second(0x7777, 0x88889999, 51002);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    wake = [&] {
        std::array<std::byte, 2048> buf{};
        ASSERT_GT(probe.stage(buf), 0);
        ASSERT_TRUE(probe.capture(reply(first, addr("1.1.1.1"), addr("10.8.0.2"), kRcodeNoError)));
    };
    ASSERT_EQ(probe.run(first, std::chrono::milliseconds(500)), ProbeOutcome::Answered);

    bool stole_stale = false;
    wake = [&] {
        std::array<std::byte, 2048> buf{};
        ASSERT_GT(probe.stage(buf), 0);
        stole_stale = probe.capture(reply(first, addr("1.1.1.1"), addr("10.8.0.2"), kRcodeNoError));
        probe.abort();
    };

    EXPECT_EQ(probe.run(second, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_FALSE(stole_stale) << "a reply carrying the previous probe's port was stolen";
}

TEST(HealthDatagramProbe, DatagramLargerThanTheBufferIsNotStaged) {
    const auto resolvers = fullTunnelPool();
    const DnsQuery query(0x1111, 0x22223333, 51000);

    std::function<void()> wake;
    DatagramProbe probe(resolvers, [&wake] { wake(); });

    int into_small = -1;
    int into_large = -1;
    wake = [&] {
        std::array<std::byte, 8> small{};
        into_small = probe.stage(small);
        std::array<std::byte, 2048> large{};
        into_large = probe.stage(large);
        probe.abort();
    };

    EXPECT_EQ(probe.run(query, std::chrono::milliseconds(500)), ProbeOutcome::NotRun);
    EXPECT_EQ(into_small, 0) << "the probe was truncated into a buffer too small to hold it";
    EXPECT_GT(into_large, 0) << "a rejected small buffer consumed the staged datagram";
}

TEST(HealthDatagramProbe, SilentTunnelIsAFailure) {
    const auto resolvers = fullTunnelPool();
    DatagramProbe probe(resolvers, [] {});

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)),
              ProbeOutcome::Failed);
}

TEST(HealthControlProbe, NoBindSocketIsNoEvidence) {
    LoopbackResolver resolver;
    ASSERT_TRUE(resolver.ready());
    ControlProbe probe(ControlProbe::BindSocket{}, resolver.peer());

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)),
              ProbeOutcome::NotRun)
        << "with no way to protect the socket the probe must not fabricate a verdict";
}

TEST(HealthControlProbe, TheDescriptorIsOfferedBeforeAnyTrafficLeavesIt) {
    LoopbackResolver resolver;
    ASSERT_TRUE(resolver.ready());

    int offered_fd = -1;
    int offered_family = 0;
    ControlProbe probe(
        [&](int fd, int family) {
            offered_fd = fd;
            offered_family = family;
        },
        resolver.peer());

    const auto outcome = probe.run(DnsQuery(0x1234, 0x5678, 51000), std::chrono::milliseconds(10));

    EXPECT_NE(outcome, ProbeOutcome::NotRun);
    EXPECT_GE(offered_fd, 0) << "the socket was never offered for protection";
    EXPECT_EQ(offered_family, AF_INET);
}

TEST(HealthControlProbe, NoUplinkResolverIsNoEvidence) {
    ControlProbe probe([](int, int) {}, std::nullopt);

    EXPECT_EQ(probe.run(DnsQuery(1, 2, 51000), std::chrono::milliseconds(10)),
              ProbeOutcome::NotRun)
        << "with no resolver reachable off the tunnel the probe must not fabricate a verdict";
}

TEST(HealthControlProbe, AnsweredWhenUplinkResolverReplies) {
    LoopbackResolver resolver;
    ASSERT_TRUE(resolver.ready());
    resolver.answer(false);

    ControlProbe probe([](int, int) {}, resolver.peer());

    EXPECT_EQ(probe.run(DnsQuery(0x1234, 0x5678, 51000), std::chrono::seconds(2)),
              ProbeOutcome::Answered);
}

TEST(HealthControlProbe, ForeignDatagramIsIgnoredUntilAnswerArrives) {
    LoopbackResolver resolver;
    ASSERT_TRUE(resolver.ready());
    resolver.answer(true);

    ControlProbe probe([](int, int) {}, resolver.peer());

    EXPECT_EQ(probe.run(DnsQuery(0x1234, 0x5678, 51000), std::chrono::seconds(2)),
              ProbeOutcome::Answered)
        << "a datagram that was not the answer ended the exchange";
}

TEST(HealthControlProbe, SilentResolverIsAFailure) {
    LoopbackResolver resolver;
    ASSERT_TRUE(resolver.ready());

    ControlProbe probe([](int, int) {}, resolver.peer());

    EXPECT_EQ(probe.run(DnsQuery(0x1234, 0x5678, 51000), std::chrono::milliseconds(300)),
              ProbeOutcome::Failed);
}

TEST(HealthControlProbe, AbortMidWaitIsNoEvidence) {
    LoopbackResolver resolver;
    ASSERT_TRUE(resolver.ready());

    ControlProbe probe([](int, int) {}, resolver.peer());
    std::thread aborter([&probe] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        probe.abort();
    });

    const auto started = std::chrono::steady_clock::now();
    const auto outcome = probe.run(DnsQuery(0x1234, 0x5678, 51000), std::chrono::seconds(30));
    const auto took = std::chrono::steady_clock::now() - started;
    aborter.join();

    EXPECT_EQ(outcome, ProbeOutcome::NotRun) << "an aborted probe must not fabricate a verdict";
    EXPECT_LT(took, std::chrono::seconds(5)) << "abort waited out the probe timeout";
}
