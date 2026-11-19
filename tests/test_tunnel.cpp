#include "mock/memproxy.h"
#include "tunnel.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "xtun.h"

#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>

using namespace libxtun;

class TunnelTestBase : public testing::Test
{
public:
    void SetUp() override
    {
        if (!test::privileged()) {
            GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
        }
    }
};

class TunnelTestOpts : public TunnelTestBase
{
};

TEST_F(TunnelTestOpts, AttachesProxy)
{
    test::Logger log;
    test::TunOpts opts;
    test::MemProxy proxy(log.defaultCallbacks());

    auto res = Tunnel::fromOpts(opts.get());
    EXPECT_TRUE(res) << "Tunnel::fromOpts failed with " << res.error() << " error code";
    auto &tunnel = res.value();

    EXPECT_EQ(tunnel->attachProxy(&proxy), 0);
}

TEST_F(TunnelTestOpts, OwnRouteUpdatesDoNotRestartProxy)
{
#ifdef __linux__
    GTEST_SKIP() << "skipped: Linux sends no route notifications";
#endif
    test::Logger log;
    test::TunOpts opts;

    ProxyProfile configured;
    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0") };
    std::atomic<bool> restarted = false;
    test::MemProxy proxy(log.defaultCallbacks(), configured, { *net::IpPrefix::parse("192.0.2.0/24") },
                         { *net::IpPrefix::parse("192.0.2.128/25") });
    proxy.setEventListener([&](ProxyEvent ev) {
        if (ev == ProxyEvent::Down) {
            restarted = true;
        }
    });

    auto res = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(res) << "Tunnel::fromOpts failed with " << res.error() << " error code";
    auto &tunnel = res.value();

    ASSERT_EQ(tunnel->attachProxy(&proxy), 0);
    restarted = false;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_FALSE(restarted) << "the proxy was restarted for the routes xtun added itself";
}

#ifndef WIN32
class TunnelTestTunfactory : public TunnelTestBase
{
};

TEST_F(TunnelTestTunfactory, RejectsInvalidFactory)
{
    test::Logger log;
    test::MemProxy proxy(log.defaultCallbacks());

    auto res = Tunnel::fromTunfactory(nullptr, {});
    ASSERT_FALSE(res);
    ASSERT_EQ(res.error(), LIBXTUN_ERR_INVALID_ARGS);
}

TEST_F(TunnelTestTunfactory, AttachesProxy)
{
    test::Logger log;
    test::MemProxy proxy(log.defaultCallbacks());

    auto res = Tunnel::fromTunfactory(
            [&](std::vector<net::IpAddress> &dns, std::vector<net::IpPrefix> &includeRoutes,
                std::vector<net::IpPrefix> &excludeRoutes, int mtu) {
                auto tun = libxtun::test::createTun();
                if (!tun) {
                    return -1;
                }
                return tun->first.release();
            },
            { "10.0.0.1" });
    EXPECT_TRUE(res) << "Tunnel::fromTunfactory failed with " << res.error() << " error code";
    auto &tunnel = res.value();

    EXPECT_EQ(tunnel->attachProxy(&proxy), 0);
}

TEST_F(TunnelTestTunfactory, PassesRoutesAndExcludes)
{
    test::Logger log;

    ProxyProfile profile;
    profile.routes = { *net::IpPrefix::parse("0.0.0.0/0") };
    const std::vector<net::IpPrefix> includes { *net::IpPrefix::parse("10.0.0.0/8") };
    const std::vector<net::IpPrefix> excludes { *net::IpPrefix::parse("10.1.0.0/16") };
    test::MemProxy proxy(log.defaultCallbacks(), profile, includes, excludes);

    std::vector<net::IpPrefix> receivedIncludeRoutes;
    std::vector<net::IpPrefix> receivedExcludeRoutes;
    auto res = Tunnel::fromTunfactory(
            [&](std::vector<net::IpAddress> &dns, std::vector<net::IpPrefix> &includeRoutes,
                std::vector<net::IpPrefix> &excludeRoutes, int mtu) {
                receivedIncludeRoutes = includeRoutes;
                receivedExcludeRoutes = excludeRoutes;
                auto tun = libxtun::test::createTun();
                if (!tun) {
                    return -1;
                }
                return tun->first.release();
            },
            { "10.0.0.1" });
    ASSERT_TRUE(res) << "Tunnel::fromTunfactory failed with " << res.error() << " error code";
    auto &tunnel = res.value();

    ASSERT_EQ(tunnel->attachProxy(&proxy), 0);
    EXPECT_EQ(receivedIncludeRoutes, includes) << "the factory did not get the resolved routes";
    EXPECT_EQ(receivedExcludeRoutes, excludes) << "the factory did not get the excludes";
}
#endif // WIN32
