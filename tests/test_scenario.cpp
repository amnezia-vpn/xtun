#include "mock/memserver.h"
#include "mock/memtun.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "util/socket.h"
#include "util/status.h"
#include "xtun.h"

#include "gtest/gtest.h"
#include <chrono>
#include <gtest/gtest.h>

using namespace std::chrono;
using namespace libxtun;

namespace
{
    constexpr uint16_t PORT = 12345;
}

#define EXPECT_XMIT(srv)                                                                                               \
    {                                                                                                                  \
        int sock = test::udpOpen(test::DEFAULT_ROUTE, PORT);                                                           \
        ASSERT_GT(sock, 0);                                                                                            \
                                                                                                                       \
        std::vector<std::byte> bytes { 100, std::byte(0xFA) };                                                         \
        ASSERT_EQ(send(sock, reinterpret_cast<const char *>(bytes.data()), bytes.size(), 0), bytes.size());            \
                                                                                                                       \
        /* While theoretically we should check if received bytes correspond with the sent ones,                        \
         *  We cannot do that currently by the number of reasons:                                                      \
         *  - MemServer receives L3, so we should fully parse IP packet                                                \
         *  - Windows translate unicast routes to all newly-created interfaces                                         \
         *  Maybe it does not worth it.                                                                                \
         * FIXME: anyways                                                                                              \
         */                                                                                                            \
        std::byte any;                                                                                                 \
        EXPECT_GT(srv.tun().waitForArrival({ &any, 1 }, std::chrono::milliseconds(200)), 0);                           \
    }

class ScenarioConfpair : public testing::TestWithParam<test::Confpair>
{
};

TEST_P(ScenarioConfpair, CommonUse)
{
    if (!test::privileged()) {
        GTEST_SKIP() << "skipped: test requires root/Administrator";
    }

    const auto &[_a, proto, conf, _b, srvConf] = GetParam();

    test::TunOpts opts;
    test::Logger log("client");
    test::SockBindRemover bindRemover;
    test::StatusChecker status;
    test::MemServer srv("server", proto, srvConf.c_str());

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxy {};
    bindRemover.wrapProxy(proxy);
    log.wrapProxy(proxy);
    status.wrapProxy(proxy);

    EXPECT_EQ(libxtun_proxy_new(&proxy, proto, conf.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    EXPECT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    EXPECT_XMIT(srv);

    libxtun_tunnel_detach_proxy(&tun, &proxy);
    libxtun_proxy_free(&proxy);
    libxtun_tunnel_free(&tun);
}

TEST_P(ScenarioConfpair, SeamlessSwitch)
{
    if (!test::privileged()) {
        GTEST_SKIP() << "skipped: test requires root/Administrator";
    }

    const auto &[_a, proto, confA, confB, srvConf] = GetParam();

    test::TunOpts opts;
    test::Logger logA("A");
    test::StatusChecker statusA;
    test::Logger logB("B");
    test::StatusChecker statusB;
    test::SockBindRemover bindRemover;
    test::MemServer srv("server", proto, srvConf.c_str());

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxyA {};
    bindRemover.wrapProxy(proxyA);
    logA.wrapProxy(proxyA);
    statusA.wrapProxy(proxyA);

    EXPECT_EQ(libxtun_proxy_new(&proxyA, proto, confA.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxyA), LIBXTUN_OK);

    EXPECT_TRUE(statusA.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    EXPECT_XMIT(srv);

    libxtun_proxy proxyB {};
    bindRemover.wrapProxy(proxyB);
    logB.wrapProxy(proxyB);
    statusB.wrapProxy(proxyB);

    EXPECT_EQ(libxtun_proxy_new(&proxyB, proto, confB.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxyB), LIBXTUN_OK);
    libxtun_tunnel_detach_proxy(&tun, &proxyA);
    libxtun_proxy_free(&proxyA);

    EXPECT_TRUE(statusB.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    EXPECT_XMIT(srv);

    libxtun_tunnel_detach_proxy(&tun, &proxyB);
    libxtun_proxy_free(&proxyB);
    libxtun_tunnel_free(&tun);
}

INSTANTIATE_TEST_SUITE_P(Scenario, ScenarioConfpair, testing::ValuesIn(test::ConfpairBuilder().build()),
                         [](const testing::TestParamInfo<test::Confpair> &info) { return info.param.name; });
