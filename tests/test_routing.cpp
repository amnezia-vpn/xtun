#include "proxy.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "util/status.h"
#include "xtun.h"

#include <algorithm>
#include <chrono>
#include <gtest/gtest.h>

using namespace libxtun;

class RoutingSetup : public testing::TestWithParam<test::Setup>
{
};

TEST_P(RoutingSetup, ProxyTrafficDoesNotLoopIntoTunnel)
{
    const auto &setup = GetParam();
    if (!test::privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }
    if (setup.name != "awg_real") {
        GTEST_SKIP() << "skipped: the local endpoint is delivered by the kernel's local table before any rule";
    }

    test::Logger log;
    const auto configured = Proxy::create(setup.proto, setup.clientA.c_str(), log.defaultCallbacks());
    ASSERT_TRUE(configured) << "Proxy::create failed with " << configured.error() << " error code";
    const auto routes = configured.value()->profile().routes;
    if (!std::ranges::any_of(routes, [](const net::IpPrefix &route) {
            return route.isDefaultRoute() && route.address().family() == AF_INET;
        })) {
        GTEST_SKIP() << "skipped: the real config's AllowedIPs do not cover 0.0.0.0/0";
    }

    test::StatusChecker status;
    test::TunOpts opts;

    libxtun_tunnel tun {};
    ASSERT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxy {};
    setup.wrapper->wrapProxy(proxy);
    log.wrapProxy(proxy);
    status.wrapProxy(proxy);
    const char *halves[] = { "0.0.0.0/1", "128.0.0.0/1", nullptr };
    libxtun_proxy_opts includeHalves { .size = sizeof(libxtun_proxy_opts), .includeRoutes = halves };
    ASSERT_EQ(libxtun_proxy_new(&proxy, setup.proto, setup.clientA.c_str(), &includeHalves), LIBXTUN_OK);
    ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    EXPECT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, std::chrono::seconds(5)))
            << "the proxy's endpoint inside a non-default route was looped into the tun";

    libxtun_tunnel_detach_proxy(&tun, &proxy);
    libxtun_proxy_free(&proxy);
    libxtun_tunnel_free(&tun);
}

INSTANTIATE_TEST_SUITE_P(Routing, RoutingSetup,
                         testing::ValuesIn(test::SetupBuilder().withRoutes({ "0.0.0.0/0" }).build()),
                         [](const testing::TestParamInfo<test::Setup> &info) { return info.param.name; });
