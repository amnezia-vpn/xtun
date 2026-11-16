#include "mock/memproxy.h"
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
#include <string>
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

    std::vector<std::string> toStrings(const std::vector<net::IpPrefix> &prefixes)
    {
        std::vector<std::string> out;
        for (const net::IpPrefix &prefix : prefixes) {
            out.push_back(prefix.toString());
        }
        return out;
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

TEST(ProxyProfile, IncludeIntersectsProxyRoutes)
{
    ProxyProfile configured;
    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0"), *net::IpPrefix::parse("::/0") };
    test::MemProxy fullTunnel({}, configured, { *net::IpPrefix::parse("10.0.0.0/8") });
    EXPECT_EQ(toStrings(fullTunnel.profile().includeRoutes), std::vector<std::string>({ "10.0.0.0/8" }));

    configured.routes = { *net::IpPrefix::parse("10.8.0.0/24") };
    test::MemProxy subnet({}, configured,
                          { *net::IpPrefix::parse("10.0.0.0/8"), *net::IpPrefix::parse("192.168.0.0/16") });
    EXPECT_EQ(toStrings(subnet.profile().includeRoutes), std::vector<std::string>({ "10.8.0.0/24" }));
}

TEST(ProxyProfile, ExcludeRemovesCoveredInclude)
{
    ProxyProfile configured;
    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0") };
    test::MemProxy proxy({}, configured,
                         { *net::IpPrefix::parse("10.0.0.0/8"), *net::IpPrefix::parse("192.168.0.0/16") },
                         { *net::IpPrefix::parse("192.168.0.0/16") });

    const ProxyProfile profile = proxy.profile();
    EXPECT_EQ(toStrings(profile.includeRoutes), std::vector<std::string>({ "10.0.0.0/8" }));
    EXPECT_TRUE(profile.excludeRoutes.empty());
}

TEST(ProxyProfile, ExcludeOutsideTunnelRoutesAddsNoRoute)
{
    ProxyProfile configured;
    configured.routes = { *net::IpPrefix::parse("10.8.0.0/24") };
    test::MemProxy outsideProxyRoutes({}, configured, {}, { *net::IpPrefix::parse("8.8.8.0/24") });
    EXPECT_EQ(toStrings(outsideProxyRoutes.profile().includeRoutes), std::vector<std::string>({ "10.8.0.0/24" }));
    EXPECT_TRUE(outsideProxyRoutes.profile().excludeRoutes.empty());

    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0") };
    test::MemProxy outsideIncludes({}, configured, { *net::IpPrefix::parse("10.0.0.0/8") },
                                   { *net::IpPrefix::parse("192.168.0.0/16") });
    EXPECT_EQ(toStrings(outsideIncludes.profile().includeRoutes), std::vector<std::string>({ "10.0.0.0/8" }));
    EXPECT_TRUE(outsideIncludes.profile().excludeRoutes.empty());
}

TEST(ProxyProfile, MasksHostBits)
{
    ProxyProfile configured;
    configured.routes = { *net::IpPrefix::parse("10.8.0.5/24") };
    test::MemProxy hostBitsInRoute({}, configured);
    EXPECT_EQ(toStrings(hostBitsInRoute.profile().includeRoutes), std::vector<std::string>({ "10.8.0.0/24" }));

    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0") };
    test::MemProxy hostBitsInInclude({}, configured, { *net::IpPrefix::parse("10.15.255.1/13") });
    EXPECT_EQ(toStrings(hostBitsInInclude.profile().includeRoutes), std::vector<std::string>({ "10.8.0.0/13" }));

    configured.routes = { *net::IpPrefix::parse("::/0") };
    test::MemProxy hostBitsInExclude({}, configured, {}, { *net::IpPrefix::parse("2001:db8::1/32") });
    EXPECT_EQ(toStrings(hostBitsInExclude.profile().excludeRoutes), std::vector<std::string>({ "2001:db8::/32" }));

    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0"), *net::IpPrefix::parse("192.0.2.7/32") };
    test::MemProxy noHostBits({}, configured);
    EXPECT_EQ(toStrings(noHostBits.profile().includeRoutes),
              std::vector<std::string>({ "0.0.0.0/0", "192.0.2.7/32" }));
}

TEST(ProxyProfile, DuplicatesRemoved)
{
    ProxyProfile configured;
    configured.routes = { *net::IpPrefix::parse("0.0.0.0/0"), *net::IpPrefix::parse("10.0.0.0/8") };
    test::MemProxy proxy({}, configured, { *net::IpPrefix::parse("10.1.0.0/16") },
                         { *net::IpPrefix::parse("10.1.2.0/24"), *net::IpPrefix::parse("10.1.2.0/24") });

    const ProxyProfile profile = proxy.profile();
    EXPECT_EQ(toStrings(profile.includeRoutes), std::vector<std::string>({ "10.1.0.0/16" }));
    EXPECT_EQ(toStrings(profile.excludeRoutes), std::vector<std::string>({ "10.1.2.0/24" }));
}
