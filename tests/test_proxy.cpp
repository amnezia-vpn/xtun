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

class ProxySetup : public testing::TestWithParam<libxtun::test::Setup>
{
};

TEST_P(ProxySetup, DeclinesInvalidConfiguration)
{
    const auto &p = GetParam();
    const auto proto = p.proto;

    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, "0xd34db33f", log.defaultCallbacks());
    EXPECT_FALSE(res) << "Proxy::create initialized with invalid configuration";
}

TEST_P(ProxySetup, EatsConfiguration)
{
    const auto &p = GetParam();
    const auto proto = p.proto;
    const auto &cfg = p.clientA;

    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";
}

TEST_P(ProxySetup, AttachesNull)
{
    const auto &p = GetParam();
    const auto proto = p.proto;
    const auto &cfg = p.clientA;
    libxtun::test::Logger log;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();
    proxy->attachIo(nullptr);
}

TEST_P(ProxySetup, AttachesIo)
{
    const auto &p = GetParam();
    const auto proto = p.proto;
    const auto &cfg = p.clientA;
    libxtun::test::Logger log;

    libxtun::test::MemTun tun;

    auto res = libxtun::Proxy::create(proto, cfg.c_str(), log.defaultCallbacks());
    EXPECT_TRUE(res) << "Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();
    proxy->attachIo(&tun);
}

TEST_P(ProxySetup, Roundtrip)
{
    const auto &p = GetParam();
    const auto proto = p.proto;
    const auto &cfg = p.clientA;
    const auto wrapper = p.wrapper;
    const auto server = p.createServer("server");

    if (!server) {
        GTEST_SKIP() << "local server setup is required";
    }

    test::Logger log("client");
    test::StatusChecker status;
    test::MemTun tun;

    ClientCallbacks callbacks {};
    log.wrapCallbacks(callbacks);
    status.wrapCallbacks(callbacks);
    wrapper->wrapCallbacks(callbacks);

    auto res = Proxy::create(proto, cfg.c_str(), callbacks);
    ASSERT_TRUE(res) << "[B] Proxy::create failed with " << res.error() << " error code";

    auto &proxy = res.value();

    proxy->attachIo(&tun);
    proxy->event(ProxyEvent::Up);

    ASSERT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, seconds(5)));
}

INSTANTIATE_TEST_SUITE_P(Proxy, ProxySetup, testing::ValuesIn(libxtun::test::SetupBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Setup> &info) { return info.param.name; });
