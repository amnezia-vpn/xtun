#include "mock/memtun.h"
#include "net/ip.h"
#include "proxy.h"
#include "util/config.h"
#include "util/log.h"
#include "util/status.h"
#include "xtun.h"

#include <algorithm>
#include <chrono>
#include <gtest/gtest.h>
#include <optional>
#include <vector>

using namespace std::chrono;
using namespace libxtun;

namespace
{
    std::optional<net::IpAddress> pickFirst(std::vector<net::IpPrefix> prefixes, int family)
    {
        auto res = std::ranges::find_if(prefixes, [&](const net::IpPrefix &p) { return p.address().family() == family; });
        if (res == prefixes.end()) {
            return std::nullopt;
        }
        return res->address();
    }
}

class ProxyConfig : public testing::TestWithParam<libxtun::test::Confpair>
{
};

TEST_P(ProxyConfig, DeclinesInvalidConfiguration)
{
    const auto &[_a, proto, _b, _c, _d] = GetParam();
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, "0xd34db33f", log.defaultCallbacks());
    EXPECT_FALSE(res) << "Proxy::create initialized with invalid configuration";
}

TEST_P(ProxyConfig, EatsConfiguration)
{
    const auto &[_a, proto, cfg, _b, _c] = GetParam();
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";
}

TEST_P(ProxyConfig, AttachesNull)
{
    const auto &[_a, proto, cfg, _b, _c] = GetParam();
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();
    proxy->attachIo(nullptr);
}

TEST_P(ProxyConfig, AttachesIo)
{
    const auto &[_a, proto, cfg, _b, _c] = GetParam();
    libxtun::test::Logger log;

    libxtun::test::MemTun tun;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();
    proxy->attachIo(&tun);
}

TEST_P(ProxyConfig, Roundtrip)
{
    auto &[_, proto, cfgA, _b, cfgB] = GetParam();

    test::Logger logA("A");
    test::Logger logB("B");
    test::StatusChecker statusA;
    test::StatusChecker statusB;
    test::MemTun tunA;
    test::MemTun tunB;

    ClientCallbacks callbacksB {};
    auto resB = Proxy::create(proto, cfgB.c_str(), logB.wrapCallbacks(statusB.wrapCallbacks(callbacksB)));
    ASSERT_TRUE(resB) << "[B] Proxy::create failed with " << resB.error() << " error code";

    ClientCallbacks callbacksA {};
    auto resA = Proxy::create(proto, cfgA.c_str(), logA.wrapCallbacks(statusA.wrapCallbacks(callbacksA)));
    ASSERT_TRUE(resA) << "[A] Proxy::create failed with " << resA.error() << " error code";

    auto &proxyB = resB.value();
    auto &proxyA = resA.value();

    proxyB->attachIo(&tunB);
    proxyB->event(ProxyEvent::Up);

    proxyA->attachIo(&tunA);
    proxyA->event(ProxyEvent::Up);

    ASSERT_TRUE(statusA.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
    ASSERT_TRUE(statusB.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
}

INSTANTIATE_TEST_SUITE_P(Proxy, ProxyConfig, testing::ValuesIn(libxtun::test::ConfpairBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Confpair> &info) { return info.param.name; });
