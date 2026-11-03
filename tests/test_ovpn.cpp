#include "mock/memtun.h"
#include "util/ovpn.h"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <stdexcept>
#include <string>

namespace
{
    using namespace std::chrono_literals;
    using libxtun::proto::Ovpn;

    std::string withoutBlock(std::string profile, const std::string &name)
    {
        const auto first = profile.find('<' + name + '>');
        const auto last = profile.find("</" + name + '>', first);
        profile.erase(first, last + name.size() + 3 - first);
        return profile;
    }
}

TEST(OvpnConfig, AcceptsInlineCredentials)
{
    auto result = Ovpn::create(libxtun::test::ovpnProfile(), {});
    ASSERT_TRUE(result.has_value());
    EXPECT_STREQ(result.value()->name(), "openvpn");
    // Local routes are published only after the transport and packet adapter are ready.
    EXPECT_TRUE(result.value()->profile().routes.empty());
    EXPECT_TRUE(result.value()->profile().dnsServers.empty());
}

TEST(OvpnConfig, RejectsInvalidProfile)
{
    auto result = Ovpn::create("client\n<ca>\nunfinished", {});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(OvpnConfig, RejectsExternalFiles)
{
    auto profile = withoutBlock(libxtun::test::ovpnProfile(), "ca");
    auto result = Ovpn::create(profile + "\nca missing-test-ca.pem\n", {});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LIBXTUN_ERR_UNSUPPORTED);
}

TEST(OvpnConfig, RequiresAllCredentialBlocks)
{
    for (const auto *name : { "ca", "cert", "key" }) {
        SCOPED_TRACE(name);
        auto result = Ovpn::create(withoutBlock(libxtun::test::ovpnProfile(), name), {});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), LIBXTUN_ERR_UNSUPPORTED);
    }
}

TEST(OvpnConfig, RejectsUnsupportedFeatures)
{
    for (const auto *option : { "auth-user-pass\n", "proto udp6\n", "up /bin/true\n", "compress lz4\n",
                                "dhcp-option DOMAIN example.test\n", "inactive 0\n", "inactive 10\n",
                                "inactive 10 1024\n", "<inactive>\n10\n</inactive>\n" }) {
        SCOPED_TRACE(option);
        auto result = Ovpn::create(libxtun::test::ovpnProfile() + option, {});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), LIBXTUN_ERR_UNSUPPORTED);
    }
}

TEST(OvpnConfig, RejectsTap)
{
    // OpenVPN3 rejects TAP in eval_config()
    auto result = Ovpn::create(libxtun::test::ovpnProfile() + "dev-type tap\n", {});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(OvpnConfig, RejectsInvalidRoute)
{
    // Ovpn requires the route destination to be the network address.
    // With a /24 mask, 10.9.0.1 has host bits set; the network address is 10.9.0.0.
    auto result = Ovpn::create(libxtun::test::ovpnProfile() + "route 10.9.0.1 255.255.255.0\n", {});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(OvpnLifecycle, NoAttemptToConnectWithoutAttachedIo)
{
    libxtun::test::TestOvpnEvents events;
    std::atomic<unsigned> sockets { 0 };
    events.onSocket = [&](int) { ++sockets; };
    auto result = Ovpn::create(libxtun::test::ovpnProfile(), events.callbacks());
    ASSERT_TRUE(result.has_value());
    auto &proxy = *result.value();

    proxy.event(libxtun::ProxyEvent::Up);
    proxy.event(libxtun::ProxyEvent::Down);
    EXPECT_EQ(sockets.load(), 0);
    EXPECT_EQ(events.disconnections.load(), 0);
}

// Down must wait until the worker returns from the user's onSocket callback.
TEST(OvpnLifecycle, DownWaitsUntilOnSocketCallbackReturns)
{
    libxtun::test::MemTun tun;
    libxtun::test::TestOvpnEvents events;
    std::promise<void> callbackStarted;
    std::promise<void> allowCallbackToReturn;
    auto callbackMayReturn = allowCallbackToReturn.get_future();
    events.onSocket = [&](int) {
        callbackStarted.set_value();
        // The worker waits here until the test calls allowCallbackToReturn.set_value().
        EXPECT_EQ(callbackMayReturn.wait_for(5s), std::future_status::ready);
    };

    auto result = Ovpn::create(libxtun::test::ovpnProfile(), events.callbacks());
    ASSERT_TRUE(result.has_value());
    auto &proxy = *result.value();
    proxy.attachIo(&tun);
    proxy.event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(callbackStarted.get_future().wait_for(2s), std::future_status::ready);

    // Call Down on another thread so the test can still release the waiting callback.
    std::promise<void> stopStarted;
    auto stopping = std::async(std::launch::async, [&]() {
        stopStarted.set_value();
        proxy.event(libxtun::ProxyEvent::Down);
    });
    EXPECT_EQ(stopStarted.get_future().wait_for(2s), std::future_status::ready);
    // The callback has not returned, so Down must still be waiting.
    EXPECT_EQ(stopping.wait_for(50ms), std::future_status::timeout);

    // Once the callback returns, Down must finish too.
    allowCallbackToReturn.set_value();
    EXPECT_EQ(stopping.wait_for(5s), std::future_status::ready);
    stopping.get();
    proxy.attachIo(nullptr);
}

TEST(OvpnLifecycle, InitialDownAllowsFirstUpAndLaterUpDoesNotRestartTheClient)
{
    libxtun::test::MemTun tun;
    libxtun::test::TestOvpnEvents events;
    std::atomic<unsigned> sockets { 0 };
    events.onSocket = [&](int) {
        ++sockets;
        // End the attempt immediately; this test does not need a VPN server.
        throw std::runtime_error("stop this test's connection attempt");
    };
    auto disconnected = events.disconnected.get_future();
    auto result = Ovpn::create(libxtun::test::ovpnProfile(), events.callbacks());
    ASSERT_TRUE(result.has_value());
    auto &proxy = *result.value();
    proxy.attachIo(&tun);

    proxy.event(libxtun::ProxyEvent::Down);
    proxy.event(libxtun::ProxyEvent::Up);
    proxy.event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(disconnected.wait_for(5s), std::future_status::ready);
    proxy.event(libxtun::ProxyEvent::Down);
    proxy.event(libxtun::ProxyEvent::Up);
    EXPECT_EQ(sockets.load(), 1);
    EXPECT_EQ(events.connections.load(), 0);
    EXPECT_EQ(events.disconnections.load(), 1);
    EXPECT_TRUE(proxy.profile().routes.empty());
    proxy.attachIo(nullptr);
}

TEST(OvpnLifecycle, SocketCallbackExceptionStopsConnectionAndReportsDisconnected)
{
    libxtun::test::MemTun tun;
    libxtun::test::TestOvpnEvents events;
    events.onSocket = [](int) { throw std::runtime_error("test socket callback failure"); };
    auto disconnected = events.disconnected.get_future();
    auto result = Ovpn::create(libxtun::test::ovpnProfile(), events.callbacks());
    ASSERT_TRUE(result.has_value());
    auto &proxy = *result.value();
    proxy.attachIo(&tun);
    proxy.event(libxtun::ProxyEvent::Up);

    EXPECT_EQ(disconnected.wait_for(5s), std::future_status::ready);
    proxy.event(libxtun::ProxyEvent::Down);
    EXPECT_EQ(events.connections.load(), 0);
    EXPECT_EQ(events.disconnections.load(), 1);
    EXPECT_TRUE(proxy.profile().routes.empty());
    proxy.attachIo(nullptr);
}

TEST(OvpnLifecycle, LogCallbackExceptionDoesNotPreventDisconnectionAfterSocketCallbackFailure)
{
    libxtun::test::MemTun tun;
    libxtun::test::TestOvpnEvents events;
    std::atomic<unsigned> logs { 0 };
    events.onLog = [&](const char *) {
        ++logs;
        throw std::runtime_error("test log callback failure");
    };
    events.onSocket = [](int) { throw std::runtime_error("stop after logging"); };
    auto disconnected = events.disconnected.get_future();
    auto result = Ovpn::create(libxtun::test::ovpnProfile(), events.callbacks());
    ASSERT_TRUE(result.has_value());
    auto &proxy = *result.value();
    proxy.attachIo(&tun);
    proxy.event(libxtun::ProxyEvent::Up);

    EXPECT_EQ(disconnected.wait_for(5s), std::future_status::ready);
    proxy.event(libxtun::ProxyEvent::Down);
    EXPECT_GT(logs.load(), 0);
    EXPECT_EQ(events.disconnections.load(), 1);
    proxy.attachIo(nullptr);
}
