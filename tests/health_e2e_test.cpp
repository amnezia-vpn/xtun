#include "health/fake_clock.h"
#include "health/manual_scheduler.h"

#include "health/datagram_probe.h"
#include "health/dns_query.h"
#include "health/monitor.h"
#include "health/monitored_io.h"
#include "health/resolver_pool.h"
#include "health/traffic_meter.h"
#include "injectable_tun.h"
#include "net/ip.h"
#include "net/network_order.h"
#include "net/socket.h"
#include "net/udp.h"
#include "proto/awg.h"
#include "proxy.h"
#include "tunnel.h"
#include "tunnel_io.h"
#include "util/random.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using libxtun::RandomSource;
using libxtun::health::ConnectionState;
using libxtun::health::ConnectivityProbe;
using libxtun::health::DatagramProbe;
using libxtun::health::DnsQuery;
using libxtun::health::DnsQueryFactory;
using libxtun::health::HealthListener;
using libxtun::health::HealthMonitor;
using libxtun::health::HealthSettings;
using libxtun::health::kDnsPort;
using libxtun::health::MonitoredIo;
using libxtun::health::ProbeOutcome;
using libxtun::health::ResolverPool;
using libxtun::health::TrafficMeter;
using libxtun::net::IpAddress;
using libxtun::net::UdpDatagramView;
using namespace std::chrono_literals;

constexpr const char *kPrivA = "YHJIKcg6kMlHqmHvpdetXH9300wKO4NxqX1L+v9h20A=";
constexpr const char *kPubA = "dpY/lgMy5OZPe6EVFl25AYL8hCsNEPxzO2uZZdzLnlo=";
constexpr const char *kPrivB = "CPbRqDXAuXNShMCXDVQ6d7mKeVAk2isLmqSNOnVWGWs=";
constexpr const char *kPubB = "sB1wCAUCSBg8mrN8n4mPMAs4Z2C9QUCu3i6Emfb9omo=";

constexpr const char *kLoopback = "127.0.0.1";
constexpr const char *kLocal = "10.9.9.1";
constexpr const char *kPeer = "10.9.9.2";
constexpr const char *kLocalPrefix = "10.9.9.1/32";
constexpr const char *kPeerPrefix = "10.9.9.2/32";

constexpr std::uint16_t kResponseFlags = 0x8180;
constexpr auto kHandshakeTimeout = 6s;
constexpr auto kTrafficTimeout = 3s;
constexpr auto kStatusTimeout = 12s;

constexpr const char *kAwgParams =
    "Jc = 2\n"
    "Jmin = 8\n"
    "Jmax = 16\n"
    "S1 = 4\n"
    "S2 = 6\n"
    "H1 = 1234567891\n"
    "H2 = 1234567892\n"
    "H3 = 1234567893\n"
    "H4 = 1234567894\n";

std::string confText(const char *key, int listen_port, const char *peer_key,
                     const std::string &endpoint_host, int peer_port, const char *allowed,
                     const char *dns = nullptr) {
    return std::string("[Interface]\n") + "PrivateKey = " + key + "\n" +
        "ListenPort = " + std::to_string(listen_port) + "\n" +
        (dns == nullptr ? std::string{} : std::string("DNS = ") + dns + "\n") + kAwgParams +
        "\n"
        "[Peer]\n" +
        "PublicKey = " + peer_key + "\n" + "Endpoint = " + endpoint_host + ":" +
        std::to_string(peer_port) + "\n" + "AllowedIPs = " + allowed + "\n";
}

libxtun::proto::awg::Config conf(const char *key, int listen_port, const char *peer_key,
                                 const std::string &endpoint_host, int peer_port,
                                 const char *allowed) {
    return libxtun::proto::awg::Config::fromConf(
               confText(key, listen_port, peer_key, endpoint_host, peer_port, allowed))
        .value();
}

std::string physicalIpv4() {
    auto socket = libxtun::net::Socket::udp(AF_INET);
    if (!socket) {
        return {};
    }
    const auto elsewhere = IpAddress::parse("8.8.8.8");
    if (!elsewhere || !socket->connect(libxtun::net::SockAddr(*elsewhere, kDnsPort))) {
        return {};
    }

    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (::getsockname(libxtun::net::fromAbiDescriptor(socket->native()),
                      reinterpret_cast<sockaddr *>(&local), &len) != 0) {
        return {};
    }
    char text[INET_ADDRSTRLEN] = {0};
    if (::inet_ntop(AF_INET, &local.sin_addr, text, sizeof(text)) == nullptr) {
        return {};
    }
    return text;
}

class FakeControlProbe final : public ConnectivityProbe {
  public:
    std::atomic<ProbeOutcome> outcome{ProbeOutcome::NotRun};
    std::atomic<int> runs{0};

    ProbeOutcome run(const DnsQuery &, std::chrono::milliseconds) override {
        ++runs;
        return outcome.load();
    }

    void abort() noexcept override {}
};

class RecordingListener final : public HealthListener {
  public:
    void onConnectionState(ConnectionState state) noexcept override {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_states.push_back(state);
    }

    std::vector<ConnectionState> states() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_states;
    }

  private:
    mutable std::mutex m_mtx;
    std::vector<ConnectionState> m_states;
};

class StatusSpy {
  public:
    static void handler(int status, void *priv) {
        static_cast<StatusSpy *>(priv)->record(status);
    }

    bool await(int status, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(m_mtx);
        return m_cond.wait_for(lock, timeout, [this, status] {
            return std::find(m_values.begin(), m_values.end(), status) != m_values.end();
        });
    }

    std::vector<int> values() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_values;
    }

  private:
    void record(int status) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_values.push_back(status);
        m_cond.notify_all();
    }

    mutable std::mutex m_mtx;
    std::condition_variable m_cond;
    std::vector<int> m_values;
};

std::vector<std::byte> ipv4Packet(const char *source, const char *destination,
                                  std::string_view payload) {
    const auto from = IpAddress::parse(source);
    const auto to = IpAddress::parse(destination);
    if (!from || !to) {
        return {};
    }

    std::vector<std::byte> packet(20 + payload.size(), std::byte{0});
    packet[0] = std::byte{0x45};
    libxtun::net::writeBigEndian16(packet, 2, static_cast<std::uint16_t>(packet.size()));
    packet[8] = std::byte{64};
    packet[9] = std::byte{253};
    std::memcpy(packet.data() + 12, from->octets().data(), 4);
    std::memcpy(packet.data() + 16, to->octets().data(), 4);
    std::memcpy(packet.data() + 20, payload.data(), payload.size());
    return packet;
}

std::vector<std::byte> dnsAnswerFor(const UdpDatagramView &query) {
    std::vector<std::byte> payload(query.payload().begin(), query.payload().end());
    libxtun::net::writeBigEndian16(payload, 2, kResponseFlags);
    return libxtun::net::buildUdpDatagram(query.destination(), query.source(),
                                          query.destinationPort(), query.sourcePort(), payload);
}

class PeerResolver {
  public:
    explicit PeerResolver(InjectableTun &tun) : m_tun(tun), m_thread([this] { loop(); }) {}

    ~PeerResolver() {
        m_running.store(false);
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    void mute() { m_answering.store(false); }
    void unmute() { m_answering.store(true); }

    int queries() const { return m_queries.load(); }
    int answers() const { return m_answers.load(); }

  private:
    void loop() {
        std::vector<std::byte> packet;
        while (m_running.load()) {
            if (!m_tun.awaitWrite(packet, InjectableTun::kPollSlice)) {
                continue;
            }
            const auto query = UdpDatagramView::parse(packet);
            if (!query || query->destinationPort() != kDnsPort) {
                continue;
            }
            ++m_queries;
            if (!m_answering.load()) {
                continue;
            }
            auto answer = dnsAnswerFor(*query);
            if (answer.empty()) {
                continue;
            }
            m_tun.inject(std::move(answer));
            ++m_answers;
        }
    }

    InjectableTun &m_tun;
    std::atomic<bool> m_running{true};
    std::atomic<bool> m_answering{true};
    std::atomic<int> m_queries{0};
    std::atomic<int> m_answers{0};
    std::thread m_thread;
};

bool establish(InjectableTun &local, InjectableTun &remote) {
    std::vector<std::byte> arrived;
    const auto deadline = std::chrono::steady_clock::now() + kHandshakeTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
        local.inject(ipv4Packet(kLocal, kPeer, "xtun-handshake"));
        if (remote.awaitWrite(arrived, 50ms)) {
            return true;
        }
    }
    return false;
}

HealthSettings e2eSettings() {
    HealthSettings settings;
    settings.probe_timeout = 400ms;
    return settings;
}

struct Link {
    Link(int port_local, int port_peer)
        : a(conf(kPrivA, port_local, kPubB, kLoopback, port_peer, kPeerPrefix)),
          b(conf(kPrivB, port_peer, kPubA, kLoopback, port_local, kLocalPrefix)) {}

    ~Link() {
        monitor.stop();
        devA.cancel();
        devB.cancel();
        a.stop();
        b.stop();
    }

    bool up() {
        a.setInterface("xtune2ea");
        b.setInterface("xtune2eb");
        if (a.start(io) != LIBXTUN_OK || b.start(devB) != LIBXTUN_OK) {
            return false;
        }
        a.event(libxtun::ProxyEvent::Up);
        b.event(libxtun::ProxyEvent::Up);
        return establish(devA, devB);
    }

    bool trafficFromPeer() {
        const std::uint64_t before = meter.inboundPackets();
        const auto deadline = std::chrono::steady_clock::now() + kTrafficTimeout;
        while (std::chrono::steady_clock::now() < deadline) {
            devB.inject(ipv4Packet(kPeer, kLocal, "xtun-payload"));
            for (int slice = 0; slice < 25; ++slice) {
                if (meter.inboundPackets() > before) {
                    return true;
                }
                std::this_thread::sleep_for(10ms);
            }
        }
        return false;
    }

    std::vector<ConnectionState> states() const { return listener.states(); }

    InjectableTun devA;
    InjectableTun devB;
    libxtun::proto::Awg a;
    libxtun::proto::Awg b;

    FakeClock clock;
    RandomSource random{7};
    DnsQueryFactory queries{random};
    TrafficMeter meter;
    ResolverPool resolvers{std::vector<std::string>{kPeer}, std::vector<std::string>{kLocalPrefix},
                           std::vector<std::string>{kPeerPrefix}};
    DatagramProbe tunnel{resolvers, [this] { devA.wake(); }};
    FakeControlProbe control;
    MonitoredIo io{devA, meter, tunnel};
    ManualScheduler scheduler;
    RecordingListener listener;
    HealthSettings settings = e2eSettings();
    HealthMonitor monitor{settings, listener, meter, tunnel, control, queries, scheduler, clock};
};

}  // namespace

TEST(HealthE2E, ClientIsToldConnectedWhenProbeCrossesTunnel) {
    constexpr int kPortLocal = 56821;
    constexpr int kPortPeer = 56822;

    const std::string host = physicalIpv4();
    if (host.empty()) {
        GTEST_SKIP() << "no physical default route to host the peer endpoint";
    }

    StatusSpy spy;
    libxtun_proxy client{};
    client.statushandler = &StatusSpy::handler;
    client.statushandler_priv = &spy;
    ASSERT_EQ(
        libxtun_proxy_new(
            &client, LIBXTUN_PROXY_PROTO_AWG,
            confText(kPrivA, kPortLocal, kPubB, host, kPortPeer, kPeerPrefix, kPeer).c_str()),
        LIBXTUN_OK);

    const char *addrs[] = {kLocalPrefix, nullptr};
    libxtun_tunnel_opts opts{};
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
    opts.if_addrs = addrs;
    opts.health_seconds = 5;

    InjectableTun devA;
    InjectableTun devB;
    libxtun::proto::Awg peer(conf(kPrivB, kPortPeer, kPubA, host, kPortLocal, kLocalPrefix));
    peer.setInterface("xtune2eb");

    {
        libxtun::Tunnel tunnel(opts);
        auto *attached = reinterpret_cast<libxtun::Proxy *>(client.handle);
        ASSERT_EQ(tunnel.attachProxy(attached, devA), LIBXTUN_OK);
        ASSERT_EQ(peer.start(devB), LIBXTUN_OK);
        attached->event(libxtun::ProxyEvent::Up);
        peer.event(libxtun::ProxyEvent::Up);

        const bool session = establish(devA, devB);
        PeerResolver resolver(devB);
        const bool connected = spy.await(LIBXTUN_STATUS_CONNECTED, kStatusTimeout);
        const int queries = resolver.queries();

        devA.cancel();
        devB.cancel();

        EXPECT_TRUE(session) << "the two peers never established a session";
        EXPECT_TRUE(connected) << "the client was never told the tunnel is up";
        EXPECT_GE(queries, 1) << "the status was reported without a probe crossing the tunnel";
        EXPECT_EQ(spy.values(), std::vector<int>{LIBXTUN_STATUS_CONNECTED});
    }

    peer.stop();
    libxtun_proxy_free(&client);
}

TEST(HealthE2E, StatusFollowsTrafficThenSilenceUntilTunnelIsDeclaredDead) {
    Link link(56823, 56824);
    ASSERT_TRUE(link.up()) << "the two peers never established a session";
    PeerResolver resolver(link.devB);
    ASSERT_TRUE(link.trafficFromPeer()) << "no traffic arrived through the tunnel";

    link.monitor.start();
    ASSERT_TRUE(link.scheduler.fire().has_value());
    ASSERT_EQ(link.states(), std::vector<ConnectionState>{ConnectionState::Connected});
    ASSERT_EQ(resolver.queries(), 0) << "a tunnel carrying traffic was probed anyway";

    const std::size_t delivered = link.devA.written();
    const std::uint64_t metered = link.meter.counters().inbound_packets;

    ASSERT_TRUE(link.scheduler.fire().has_value());
    EXPECT_GE(resolver.answers(), 1) << "the quiet tunnel was never probed";
    EXPECT_EQ(link.states().size(), 1u) << "the client was told Connected twice";
    EXPECT_EQ(link.devA.written(), delivered) << "the probe answer was written to the tun";
    EXPECT_EQ(link.meter.counters().inbound_packets, metered)
        << "the probe answer was metered as user traffic";

    resolver.mute();
    link.control.outcome.store(ProbeOutcome::Answered);

    ASSERT_TRUE(link.scheduler.fire().has_value());
    EXPECT_EQ(link.states().size(), 1u) << "one lost probe tore the tunnel down";

    EXPECT_FALSE(link.scheduler.fire().has_value()) << "a Disconnected verdict must end the loop";

    const auto states = link.states();
    ASSERT_EQ(states.size(), 2u);
    EXPECT_EQ(states[1], ConnectionState::Disconnected);
    EXPECT_EQ(link.control.runs.load(), 1);
    EXPECT_FALSE(link.monitor.running());
}

TEST(HealthE2E, OfflineHostIsNoNetworkAndTrafficComingBackClearsIt) {
    Link link(56825, 56826);
    ASSERT_TRUE(link.up());
    PeerResolver resolver(link.devB);
    resolver.mute();
    link.control.outcome.store(ProbeOutcome::Failed);

    link.monitor.start();
    link.scheduler.fire();
    const auto backoff = link.scheduler.fire();

    ASSERT_EQ(link.states(), std::vector<ConnectionState>{ConnectionState::NoNetwork});
    ASSERT_TRUE(backoff.has_value());
    EXPECT_EQ(*backoff,
              std::chrono::duration_cast<std::chrono::milliseconds>(link.settings.period) *
                  link.settings.no_network_backoff);

    const int control_runs = link.control.runs.load();
    resolver.unmute();
    ASSERT_TRUE(link.trafficFromPeer());
    ASSERT_TRUE(link.scheduler.fire().has_value());

    const auto states = link.states();
    ASSERT_EQ(states.size(), 2u);
    EXPECT_EQ(states[1], ConnectionState::Connected);
    EXPECT_EQ(link.control.runs.load(), control_runs)
        << "real traffic had to prove itself with a probe";
}
