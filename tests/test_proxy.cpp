#include "mock/memtun.h"
#include "proxy.h"
#include "util/config.h"
#include "util/log.h"
#include "util/sample.h"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

class ProxyConfig : public testing::TestWithParam<libxtun::test::Confpair>
{
};

TEST_P(ProxyConfig, DeclinesInvalidConfiguration)
{
    const auto &[_a, proto, _b, _c] = GetParam();
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, "0xd34db33f", log.defaultCallbacks());
    EXPECT_FALSE(res) << "Proxy::create initialized with invalid configuration";
}

TEST_P(ProxyConfig, EatsConfiguration)
{
    const auto &[_a, proto, cfg, _b] = GetParam();
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";
}

TEST_P(ProxyConfig, AttachesNull)
{
    const auto &[_a, proto, cfg, _b] = GetParam();
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();
    proxy->attachIo(nullptr);
}

TEST_P(ProxyConfig, AttachesIo)
{
    const auto &[_a, proto, cfg, _b] = GetParam();
    libxtun::test::Logger log;

    libxtun::test::MemTun tun;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();
    proxy->attachIo(&tun);
}

TEST_P(ProxyConfig, Roundtrip)
{
    auto &[_, proto, cfgA, cfgB] = GetParam();

    libxtun::test::Logger logA("A");
    libxtun::test::Logger logB("B");
    libxtun::test::MemTun tunA;
    libxtun::test::MemTun tunB;

    auto resB = libxtun::Proxy::create(proto, cfgB.c_str(), logB.defaultCallbacks());
    EXPECT_TRUE(resB) << "[B] Proxy::create failed with " << resB.error() << " error code";

    auto resA = libxtun::Proxy::create(proto, cfgA.c_str(), logA.defaultCallbacks());
    EXPECT_TRUE(resA) << "[A] Proxy::create failed with " << resA.error() << " error code";

    auto &proxyB = resB.value();
    auto &proxyA = resA.value();

    proxyB->attachIo(&tunB);
    proxyB->event(libxtun::ProxyEvent::Up);

    proxyA->attachIo(&tunA);
    proxyA->event(libxtun::ProxyEvent::Up);

    // FIXME: implement Proxy::awaitUp() and remove this workaround
    std::this_thread::sleep_for(std::chrono::seconds(2));

    const auto pkt = libxtun::test::sampleIpv4Packet("ping");
    tunA.injectPacket(pkt);

    std::vector<std::byte> rcvBuf(pkt.size());
    bool res = tunB.waitForArrival(rcvBuf, std::chrono::milliseconds(500));
    EXPECT_TRUE(res) << "failed to receive data";
}

INSTANTIATE_TEST_SUITE_P(Proxy, ProxyConfig, testing::ValuesIn(libxtun::test::ConfpairBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Confpair> &info) { return info.param.name; });
