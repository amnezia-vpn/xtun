#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "util/status.h"
#include "xtun.h"

#include "gtest/gtest.h"
#include <chrono>
#include <gtest/gtest.h>

using namespace std::chrono;
using namespace libxtun;

namespace
{
    constexpr const char *PROBE_HOST = "example.com";
    constexpr uint16_t PROBE_PORT = 443;
    const std::vector<std::string> PROBE_ADDRS = test::resolve(PROBE_HOST);
}

class ScenarioSetup : public testing::TestWithParam<test::Setup>
{
protected:
    void SetUp() override
    {
        if (!test::privileged()) {
            GTEST_SKIP() << "skipped: test requires root/Administrator";
        }
        ASSERT_FALSE(PROBE_ADDRS.empty()) << "failed to resolve " << PROBE_HOST;
    }
};

TEST_P(ScenarioSetup, CommonUse)
{
    const auto &p = GetParam();
    [[maybe_unused]] const auto srv = p.createServer("server");

    // TODO(ygurov): use killswitch in scenario tests
    test::TunOpts opts;
    test::Logger log("client");
    test::StatusChecker status;

    libxtun_tunnel tun {};
    ASSERT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxy {};
    p.wrapper->wrapProxy(proxy);
    log.wrapProxy(proxy);
    status.wrapProxy(proxy);

    ASSERT_EQ(libxtun_proxy_new(&proxy, p.proto, p.clientA.c_str()), LIBXTUN_OK);
    ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    ASSERT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    [[maybe_unused]] auto [sock, err] = test::tcpConnect(PROBE_ADDRS.front(), PROBE_PORT, seconds(5));
    ASSERT_EQ(err, 0);

    libxtun_tunnel_detach_proxy(&tun, &proxy);
    libxtun_proxy_free(&proxy);
    libxtun_tunnel_free(&tun);
}

TEST_P(ScenarioSetup, SeamlessSwitch)
{
    const auto &p = GetParam();
    [[maybe_unused]] const auto srv = p.createServer("server");
    if (!p.clientB) {
        GTEST_SKIP() << "skipped: test requires two configs defined";
    }

    test::TunOpts opts;
    test::Logger logA("A");
    test::StatusChecker statusA;
    test::Logger logB("B");
    test::StatusChecker statusB;

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxyA {};
    p.wrapper->wrapProxy(proxyA);
    logA.wrapProxy(proxyA);
    statusA.wrapProxy(proxyA);

    EXPECT_EQ(libxtun_proxy_new(&proxyA, p.proto, p.clientA.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxyA), LIBXTUN_OK);

    EXPECT_TRUE(statusA.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    [[maybe_unused]] auto [sockA, errA] = test::tcpConnect(PROBE_ADDRS.front(), PROBE_PORT, seconds(5));
    ASSERT_EQ(errA, 0);

    libxtun_proxy proxyB {};
    p.wrapper->wrapProxy(proxyB);
    logB.wrapProxy(proxyB);
    statusB.wrapProxy(proxyB);

    EXPECT_EQ(libxtun_proxy_new(&proxyB, p.proto, p.clientB->c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxyB), LIBXTUN_OK);
    libxtun_tunnel_detach_proxy(&tun, &proxyA);
    libxtun_proxy_free(&proxyA);

    EXPECT_TRUE(statusB.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    [[maybe_unused]] auto [sockB, errB] = test::tcpConnect(PROBE_ADDRS.front(), PROBE_PORT, seconds(5));
    ASSERT_EQ(errB, 0);

    libxtun_tunnel_detach_proxy(&tun, &proxyB);
    libxtun_proxy_free(&proxyB);
    libxtun_tunnel_free(&tun);
}

INSTANTIATE_TEST_SUITE_P(Scenario, ScenarioSetup, testing::ValuesIn(test::SetupBuilder().withRoutes(PROBE_ADDRS).build()),
                         [](const testing::TestParamInfo<test::Setup> &info) { return info.param.name; });
