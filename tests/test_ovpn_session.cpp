#include "mock/memtun.h"
#include "net/packet_builder.h"
#include "net/udp.h"
#include "util/ovpn.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <future>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using namespace std::chrono_literals;

    // Uses MemTun storage and lets a test pause a write or observe reader progress.
    class TestSessionTun final : public libxtun::TunnelIo
    {
    public:
        libxtun::test::MemTun packets;
        std::function<void()> onWrite;
        std::function<void()> onRead;
        int tunMtu = 1280;

        int read(std::span<std::byte> buffer) override
        {
            const auto size = packets.read(buffer);
            if (size > 0 && onRead) {
                onRead();
            }
            return size;
        }
        int write(std::span<const std::byte> packet) override
        {
            if (onWrite) {
                onWrite();
            }
            return packets.write(packet);
        }
        libxtun_error protectSocket(int fd) override
        {
            return packets.protectSocket(fd);
        }
        void wake() override
        {
            packets.wake();
        }
        void halt() override
        {
            packets.halt();
        }
        int mtu() const override
        {
            return tunMtu;
        }
        std::vector<libxtun::net::IpPrefix> addresses() override
        {
            return packets.addresses();
        }
    };

    // Each test gets a new client and MemTun.
    // ovpn_server.py starts the local server and creates client.ovpn in a temporary working directory.
    class OvpnSession : public testing::Test
    {
    protected:
        void SetUp() override
        {
            createProxy();
        }

        void createProxy(const std::string &extraOptions = {})
        {
            std::ifstream input("client.ovpn");
            ASSERT_TRUE(input.is_open()) << "The test launcher must prepare client.ovpn before running the tests";

            std::string profile { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
            auto result = libxtun::proto::Ovpn::create(profile + extraOptions, m_events.callbacks());
            ASSERT_TRUE(result.has_value());

            m_proxy = std::move(result.value());
            m_listener.onChange = [](libxtun::Proxy &, const libxtun::ProxyProfile &) { return LIBXTUN_OK; };
            ASSERT_EQ(m_proxy->setProfileListener(m_listener), LIBXTUN_OK);
            m_proxy->attachIo(&m_tun);
        }

        void TearDown() override
        {
            if (m_proxy) {
                m_proxy->clearProfileListener();
                m_proxy->attachIo(nullptr);
            }
        }

        void connect()
        {
            auto connected = m_events.connected.get_future();
            m_proxy->event(libxtun::ProxyEvent::Up);
            ASSERT_EQ(connected.wait_for(5s), std::future_status::ready);
        }

        TestSessionTun m_tun;
        libxtun::test::TestOvpnEvents m_events;
        libxtun::test::TestOvpnProfileListener m_listener;
        std::unique_ptr<libxtun::proto::Ovpn> m_proxy;
    };

    std::vector<std::byte> udpPacket(const libxtun::net::IpAddress &source, std::string_view payload)
    {
        using namespace libxtun::net;
        const auto destination = libxtun::net::IpAddress::parse("10.8.0.1");
        std::vector<std::byte> packet(IpView::HEADER_LEN + UdpView::HEADER_LEN + payload.size());
        const auto built = PacketBuilder(packet)
                                   .ip(source, *destination)
                                   .udp(19081, 19080)
                                   .withPayload([payload](std::span<std::byte> buffer) {
                                       std::memcpy(buffer.data(), payload.data(), payload.size());
                                       return payload.size();
                                   })
                                   .finish();
        if (!built) {
            throw std::runtime_error("Cannot build the OpenVPN test UDP packet");
        }
        return packet;
    }
}

// Delay accepting local routes while the session is already negotiated.
// CONNECTED and the public profile must wait for successful route application.
// Server-pushed routes and DNS must not replace the local config.
TEST_F(OvpnSession, WaitsForProfileAcceptance)
{
    // The callback sends its snapshot through profileReceived; the test waits through received.
    // finishProfile.set_value() later tells the callback that it may return and accept the profile.
    std::promise<libxtun::ProxyProfile> profileReceived;
    std::promise<void> finishProfile;
    auto finishRequested = finishProfile.get_future();
    auto received = profileReceived.get_future();
    auto connected = m_events.connected.get_future();
    m_listener.onChange = [&](libxtun::Proxy &source, const libxtun::ProxyProfile &snapshot) {
        EXPECT_TRUE(source.profile().routes.empty());
        profileReceived.set_value(snapshot);
        const bool canFinish = finishRequested.wait_for(5s) == std::future_status::ready;
        EXPECT_TRUE(canFinish);
        return canFinish ? LIBXTUN_OK : LIBXTUN_ERR_SYSTEM;
    };

    // Keep the profile callback waiting. The profile and CONNECTED must remain unavailable.
    m_proxy->event(libxtun::ProxyEvent::Up);
    const bool arrived = received.wait_for(5s) == std::future_status::ready;
    EXPECT_TRUE(arrived);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
    EXPECT_EQ(connected.wait_for(50ms), std::future_status::timeout);

    // Accept local routes and check that only local routes and DNS metadata are exposed.
    finishProfile.set_value();
    if (!arrived) {
        m_proxy->event(libxtun::ProxyEvent::Down);
        return;
    }
    const auto snapshot = received.get();
    const bool ready = connected.wait_for(5s) == std::future_status::ready;
    EXPECT_TRUE(ready);
    if (!ready) {
        m_proxy->event(libxtun::ProxyEvent::Down);
        return;
    }
    const auto accepted = m_proxy->profile();
    ASSERT_EQ(accepted.routes.size(), 2);
    ASSERT_EQ(snapshot.routes.size(), 2);
    EXPECT_EQ(accepted.routes.front().toString(), snapshot.routes.front().toString());
    EXPECT_EQ(accepted.routes[0].toString(), "10.8.0.0/24");
    EXPECT_EQ(accepted.routes[1].toString(), "198.51.100.0/24");
    ASSERT_EQ(accepted.dnsServers.size(), 1);
    EXPECT_EQ(accepted.dnsServers.front().toString(), "192.0.2.53");

    // Stopping clears the accepted profile and sends DISCONNECTED once.
    m_proxy->event(libxtun::ProxyEvent::Down);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
    EXPECT_TRUE(m_proxy->profile().dnsServers.empty());
    EXPECT_EQ(m_events.connections.load(), 1);
    EXPECT_EQ(m_events.disconnections.load(), 1);
}

// Reject local route application. A negotiated session must not become CONNECTED when its routes failed.
TEST_F(OvpnSession, RejectsFailedLocalRoutes)
{
    std::atomic<unsigned> profileCallbacks { 0 };
    m_listener.onChange = [&](libxtun::Proxy &, const libxtun::ProxyProfile &) {
        ++profileCallbacks;
        return LIBXTUN_ERR_SYSTEM;
    };
    auto disconnected = m_events.disconnected.get_future();
    m_proxy->event(libxtun::ProxyEvent::Up);

    EXPECT_EQ(disconnected.wait_for(5s), std::future_status::ready);
    m_proxy->event(libxtun::ProxyEvent::Down);
    EXPECT_EQ(profileCallbacks.load(), 1);
    EXPECT_EQ(m_events.connections.load(), 0);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
    EXPECT_TRUE(m_proxy->profile().dnsServers.empty());
}

TEST_F(OvpnSession, RejectsIncompatibleTunMtu)
{
    m_tun.tunMtu = 1420;
    std::atomic<bool> rejected { false };
    std::atomic<unsigned> profileCallbacks { 0 };
    m_events.onLog = [&](const char *message) {
        if (std::string_view(message).find("existing TUN MTU exceeds session MTU") != std::string_view::npos) {
            rejected.store(true);
        }
    };
    m_listener.onChange = [&](libxtun::Proxy &, const libxtun::ProxyProfile &) {
        ++profileCallbacks;
        return LIBXTUN_OK;
    };
    auto disconnected = m_events.disconnected.get_future();
    m_proxy->event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(disconnected.wait_for(5s), std::future_status::ready);
    m_proxy->event(libxtun::ProxyEvent::Down);
    EXPECT_TRUE(rejected.load());
    EXPECT_EQ(profileCallbacks.load(), 0);
    EXPECT_EQ(m_events.connections.load(), 0);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
}

TEST_F(OvpnSession, RejectsLocalRouteCoveringServer)
{
    m_proxy.reset();
    createProxy("route 127.0.0.0 255.0.0.0\n");
    ASSERT_FALSE(HasFatalFailure());
    std::atomic<bool> rejected { false };
    m_events.onLog = [&](const char *message) {
        if (std::string_view(message).find("local route 127.0.0.0/8 includes VPN server 127.0.0.1")
            != std::string_view::npos) {
            rejected.store(true);
        }
    };
    auto disconnected = m_events.disconnected.get_future();
    m_proxy->event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(disconnected.wait_for(5s), std::future_status::ready);
    m_proxy->event(libxtun::ProxyEvent::Down);
    EXPECT_TRUE(rejected.load());
    EXPECT_EQ(m_events.connections.load(), 0);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
}

TEST_F(OvpnSession, MapsLocalRedirectGatewayToPolicyDefault)
{
    m_proxy.reset();
    createProxy("redirect-gateway def1\n");
    ASSERT_FALSE(HasFatalFailure());
    connect();
    ASSERT_FALSE(HasFatalFailure());
    const auto profile = m_proxy->profile();
    ASSERT_EQ(profile.routes.size(), 3);
    EXPECT_EQ(profile.routes.back().toString(), "0.0.0.0/0");
    EXPECT_TRUE(std::none_of(profile.routes.begin(), profile.routes.end(), [](const auto &route) {
        return route.bits() == 1;
    }));
}

// Request Down state while the profile callback is still waiting; Down must wait for it to finish.
// Even if the callback then returns LIBXTUN_OK, keep the profile empty and send only DISCONNECTED status.
// A late acceptance must not turn a connection already being stopped into a connected one.
TEST_F(OvpnSession, StopsDuringProfileCallback)
{
    std::promise<void> profileStarted;
    std::promise<void> finishProfile;
    // Wait for finishProfile.set_value(); the promise and future do not start a thread.
    auto finishRequested = finishProfile.get_future();
    // publishProfile() calls this on the worker; waiting here pauses that worker.
    m_listener.onChange = [&](libxtun::Proxy &, const libxtun::ProxyProfile &) {
        profileStarted.set_value();
        const bool canFinish = finishRequested.wait_for(5s) == std::future_status::ready;
        EXPECT_TRUE(canFinish);
        return canFinish ? LIBXTUN_OK : LIBXTUN_ERR_SYSTEM;
    };

    // Stop while Tunnel is still applying the local routes.
    m_proxy->event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(profileStarted.get_future().wait_for(5s), std::future_status::ready);
    std::promise<void> stopStarted;
    auto stopping = std::async(std::launch::async, [&]() {
        stopStarted.set_value();
        m_proxy->event(libxtun::ProxyEvent::Down);
    });
    EXPECT_EQ(stopStarted.get_future().wait_for(2s), std::future_status::ready);
    EXPECT_EQ(stopping.wait_for(50ms), std::future_status::timeout);

    // A late successful response must not restore the profile or emit CONNECTED.
    finishProfile.set_value();
    EXPECT_EQ(stopping.wait_for(5s), std::future_status::ready);
    stopping.get();
    EXPECT_EQ(m_events.connections.load(), 0);
    EXPECT_EQ(m_events.disconnections.load(), 1);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
}

// Establish a connection with the OpenVPN server and place the IPv4/UDP packet into MemTun. Ovpn should then send it
// via the VPN to the UDP echo service on the OpenVPN server. Expect a reply in MemTun with reversed addresses and ports
// and the same payload. The source is the existing TUN address, so this also exercises remapping in both directions.
TEST_F(OvpnSession, ClientExchangesPacketsWithServer)
{
    using namespace libxtun::net;
    connect();
    ASSERT_FALSE(HasFatalFailure());
    const auto source = m_tun.addresses().front().address();
    const auto request = udpPacket(source, "xtun OpenVPN roundtrip");
    ASSERT_GE(request.size(), IpView::HEADER_LEN + UdpView::HEADER_LEN);
    const std::span<const std::byte> requestBytes(request);
    const IpView sentIp(requestBytes.first<IpView::HEADER_LEN>());
    const UdpView sentUdp(requestBytes.subspan(IpView::HEADER_LEN).first<UdpView::HEADER_LEN>());
    const auto sentPayload = requestBytes.subspan(IpView::HEADER_LEN + UdpView::HEADER_LEN);
    std::array<std::byte, 2048> reply;

    m_tun.packets.injectPacket(request);
    const auto size = m_tun.packets.waitForArrival(reply, 2s);
    ASSERT_EQ(size, static_cast<int>(request.size()));
    const std::span<const std::byte> replyBytes(reply.data(), static_cast<std::size_t>(size));
    const IpView receivedIp(replyBytes.first<IpView::HEADER_LEN>());
    ASSERT_EQ(receivedIp.version(), 4);
    ASSERT_EQ(receivedIp.protocol(), IPPROTO_UDP);
    ASSERT_GE(receivedIp.ihlBytes(), IpView::HEADER_LEN);
    ASSERT_LE(receivedIp.totalLen(), replyBytes.size());
    ASSERT_LE(receivedIp.ihlBytes() + UdpView::HEADER_LEN, receivedIp.totalLen());
    ASSERT_EQ(receivedIp.fragmentOffset(), 0);
    ASSERT_EQ(receivedIp.flags() & 1, 0);
    const auto udpBytes = replyBytes.subspan(receivedIp.ihlBytes(), receivedIp.totalLen() - receivedIp.ihlBytes());
    const UdpView receivedUdp(udpBytes.first<UdpView::HEADER_LEN>());
    ASSERT_GE(receivedUdp.length(), UdpView::HEADER_LEN);
    ASSERT_LE(receivedUdp.length(), udpBytes.size());
    const auto receivedPayload = udpBytes.subspan(UdpView::HEADER_LEN, receivedUdp.length() - UdpView::HEADER_LEN);
    EXPECT_EQ(receivedIp.srcAddress(), sentIp.dstAddress());
    EXPECT_EQ(receivedIp.dstAddress(), sentIp.srcAddress());
    EXPECT_EQ(receivedUdp.sport(), sentUdp.dport());
    EXPECT_EQ(receivedUdp.dport(), sentUdp.sport());
    EXPECT_TRUE(std::equal(receivedPayload.begin(), receivedPayload.end(), sentPayload.begin(), sentPayload.end()));
}

// Outgoing packet: test -> MemTun -> reader thread -> internal queue -> worker thread -> OpenVPN server.
// Incoming reply: OpenVPN server -> worker thread -> MemTun -> test.
// Block the worker inside its first reply write while the reader keeps filling the outgoing queue.
// Call attachIo(nullptr) on another test thread: it must wait for the active write to return.
// Release the write; detach must finish even though packets were queued for the worker.
// Expect one DISCONNECTED, an empty profile, and no new CONNECTED after a later Up.
TEST_F(OvpnSession, DetachWaitsForActiveTunWriteAndStopsClientWithQueuedOutgoingPackets)
{
    std::promise<void> writeStarted;
    std::promise<void> finishWrite;
    std::promise<void> queueFilled;
    auto finishRequested = finishWrite.get_future();
    unsigned writes = 0;
    unsigned reads = 0;
    m_tun.onWrite = [&]() {
        if (++writes == 1) {
            writeStarted.set_value();
            EXPECT_EQ(finishRequested.wait_for(5s), std::future_status::ready);
        }
    };
    m_tun.onRead = [&]() {
        if (++reads == 128) {
            queueFilled.set_value();
        }
    };
    connect();
    ASSERT_FALSE(HasFatalFailure());
    const auto packet = udpPacket(m_tun.addresses().front().address(), "queued before stop");

    // Pause the worker on the first reply, then make the reader fill and overflow its packet queue.
    m_tun.packets.injectPacket(packet);
    EXPECT_EQ(writeStarted.get_future().wait_for(2s), std::future_status::ready);
    for (unsigned i = 0; i < 256; ++i) {
        m_tun.packets.injectPacket(packet);
    }
    EXPECT_EQ(queueFilled.get_future().wait_for(2s), std::future_status::ready);

    // Detach must wait for the active write; queued packets must not keep the connection alive.
    std::promise<void> detachStarted;
    auto detaching = std::async(std::launch::async, [&]() {
        detachStarted.set_value();
        m_proxy->attachIo(nullptr);
    });
    EXPECT_EQ(detachStarted.get_future().wait_for(2s), std::future_status::ready);
    EXPECT_EQ(detaching.wait_for(50ms), std::future_status::timeout);
    finishWrite.set_value();
    EXPECT_EQ(detaching.wait_for(5s), std::future_status::ready);
    detaching.get();

    // Both connection threads have finished; later Up cannot restart this proxy.
    m_proxy->event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(m_events.connections.load(), 1);
    EXPECT_EQ(m_events.disconnections.load(), 1);
    EXPECT_TRUE(m_proxy->profile().routes.empty());
}
