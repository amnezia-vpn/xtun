#include "mock/memserver.h"
#include "mock/memtun.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "util/socket.h"
#include "xtun.h"

#include "gtest/gtest.h"
#include <chrono>
#include <gtest/gtest.h>

namespace
{
    constexpr auto ARRIVE_THRESHOLD = std::chrono::milliseconds(200);
    constexpr auto XMIT_TIMEOUT = std::chrono::seconds(5);
    constexpr uint16_t PORT = 12345;
}

#define EXPECT_XMIT(srv)                                                                                               \
    {                                                                                                                  \
        int sock = libxtun::test::udpOpen(libxtun::test::DEFAULT_ROUTE, PORT);                                         \
        ASSERT_GT(sock, 0);                                                                                            \
                                                                                                                       \
        std::vector<std::byte> bytes { 100, std::byte(0xFA) };                                                         \
        const auto start = std::chrono::steady_clock::now();                                                           \
        bool arrived = false;                                                                                          \
                                                                                                                       \
        while (std::chrono::steady_clock::now() - start < XMIT_TIMEOUT) {                                              \
            ASSERT_EQ(send(sock, reinterpret_cast<const char *>(bytes.data()), bytes.size(), 0), bytes.size());        \
                                                                                                                       \
            /* While theoretically we should check if received bytes correspond with the sent ones,                    \
             *  We cannot do that currently by the number of reasons:                                                  \
             *  - MemServer receives L3, so we should fully parse IP packet                                            \
             *  - Windows translate unicast routes to all newly-created interfaces                                     \
             *  Maybe it does not worth it.                                                                            \
             * FIXME: anyways                                                                                          \
             */                                                                                                        \
            std::byte any;                                                                                             \
            if (srv.tun().waitForArrival({ &any, 1 }, ARRIVE_THRESHOLD) > 0) {                                         \
                arrived = true;                                                                                        \
                break;                                                                                                 \
            }                                                                                                          \
        }                                                                                                              \
                                                                                                                       \
        EXPECT_TRUE(arrived);                                                                                          \
    }

class ScenarioConfpair : public testing::TestWithParam<libxtun::test::Confpair>
{
};

TEST_P(ScenarioConfpair, CommonUse)
{
    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: test requires root/Administrator";
    }

    const auto &[_a, proto, conf, srvConf] = GetParam();

    libxtun::test::TunOpts opts;
    libxtun::test::Logger log("client");
    libxtun::test::SockBindRemover bindRemover;
    libxtun::test::MemServer srv("server", proto, srvConf.c_str());

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxy {};
    bindRemover.wrapProxy(proxy);
    log.wrapProxy(proxy);

    EXPECT_EQ(libxtun_proxy_new(&proxy, proto, conf.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);
    EXPECT_XMIT(srv);

    libxtun_tunnel_detach_proxy(&tun, &proxy);
    libxtun_proxy_free(&proxy);
    libxtun_tunnel_free(&tun);
}

TEST_P(ScenarioConfpair, SeamlessSwitch)
{
    using namespace std::chrono;

    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: test requires root/Administrator";
    }

    const auto &[_a, proto, conf, srvConf] = GetParam();

    libxtun::test::TunOpts opts;
    libxtun::test::Logger logA("A");
    libxtun::test::Logger logB("B");
    libxtun::test::SockBindRemover bindRemover;
    libxtun::test::MemServer srv("server", proto, srvConf.c_str());

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxyA {};
    bindRemover.wrapProxy(proxyA);
    logA.wrapProxy(proxyA);

    EXPECT_EQ(libxtun_proxy_new(&proxyA, proto, conf.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxyA), LIBXTUN_OK);
    EXPECT_XMIT(srv);

    libxtun_proxy proxyB {};
    bindRemover.wrapProxy(proxyB);
    logB.wrapProxy(proxyB);

    EXPECT_EQ(libxtun_proxy_new(&proxyB, proto, conf.c_str()), LIBXTUN_OK);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxyB), LIBXTUN_OK);

    libxtun_tunnel_detach_proxy(&tun, &proxyA);
    libxtun_proxy_free(&proxyA);
    EXPECT_XMIT(srv);

    libxtun_tunnel_detach_proxy(&tun, &proxyB);
    libxtun_proxy_free(&proxyB);
    libxtun_tunnel_free(&tun);
}

INSTANTIATE_TEST_SUITE_P(Scenario, ScenarioConfpair, testing::ValuesIn(libxtun::test::ConfpairBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Confpair> &info) { return info.param.name; });
