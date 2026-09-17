#include "mock/memtun.h"
#include "proxy.h"
#include "util/config.h"
#include "util/log.h"
#include "util/sample.h"

#include <chrono>
#include <gtest/gtest.h>
#include <vector>

namespace
{
    constexpr auto ARRIVE_THRESHOLD = std::chrono::milliseconds(100);
    constexpr auto SETUP_TIMEOUT = std::chrono::seconds(2);
}

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

    {
        const auto sent = libxtun::test::sampleIpv4Packet("ping");
        std::vector<std::byte> received(sent.size());

        const auto start = std::chrono::steady_clock::now();
        bool arrived = false;

        while (std::chrono::steady_clock::now() - start < SETUP_TIMEOUT) {
            tunA.injectPacket(sent);

            int n = tunB.waitForArrival(received, ARRIVE_THRESHOLD);
            if (n > 0) {
                arrived = true;
                received.resize(n);
                break;
            }
        }
        // FIXME: check the actual IP addresses arrived in IP packet
        EXPECT_TRUE(arrived && received.size() == sent.size());
    }
}

INSTANTIATE_TEST_SUITE_P(Proxy, ProxyConfig, testing::ValuesIn(libxtun::test::ConfpairBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Confpair> &info) { return info.param.name; });
