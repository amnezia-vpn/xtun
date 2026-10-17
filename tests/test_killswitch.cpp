#include "killswitch.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/log.h"
#include "xtun.h"

#include <memory>
#include <string>

#include "gtest/gtest.h"

#if defined(_WIN32)
    #include "test_killswitch_windows.cpp"
#elif defined(__APPLE__)
    #include "test_killswitch_macos.cpp"
#elif defined(__linux__) && !defined(__ANDROID__)
    #include "test_killswitch_linux.cpp"
#else
    #error Unsupported platform
#endif

using namespace libxtun;

namespace libxtun::test
{
    std::unique_ptr<Killswitch> KillswitchEnv::create(libxtun_killswitch_mode mode) const
    {
        std::unique_ptr<Killswitch> killswitch = Killswitch::create(mode);
        if (killswitch == nullptr) {
            ADD_FAILURE() << "Killswitch::create returned nothing";
            return nullptr;
        }
        if (const libxtun_error rc = update(*killswitch); rc != LIBXTUN_OK) {
            ADD_FAILURE() << "Killswitch::update failed with " << rc << " error code";
            return nullptr;
        }
        return killswitch;
    }

    libxtun_error KillswitchEnv::update(Killswitch &killswitch) const
    {
        return killswitch.update(m_ifIndex, m_ifName);
    }
}

namespace
{
    std::string modeName(libxtun_killswitch_mode mode)
    {
        switch (mode) {
        case LIBXTUN_KILLSWITCH_MODE_DISABLED: return "Disabled";
        case LIBXTUN_KILLSWITCH_MODE_SOFT: return "Soft";
        case LIBXTUN_KILLSWITCH_MODE_HARD: return "Hard";
        }
        return "Unknown";
    }

    using libxtun::test::Bypass;
    using libxtun::test::LOOPBACK_V4;
    using libxtun::test::ProbeResult;
    using libxtun::test::TEST_NET_V4;
    using libxtun::test::TEST_NET_V6;
}

class KillswitchMode : public libxtun::test::KillswitchTest, public testing::WithParamInterface<libxtun_killswitch_mode>
{
};

TEST_P(KillswitchMode, BlocksUnprotectedEgress)
{
    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);
    expectProbeResult(TEST_NET_V4, Bypass::None, probeResultFor(GetParam()));
    expectProbeResult(TEST_NET_V6, Bypass::None, probeResultFor(GetParam()));
}

TEST_P(KillswitchMode, ProxyTrafficAlwaysEscapes)
{
    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered);
}

TEST_P(KillswitchMode, LoopbackStaysUsable)
{
    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);
    expectProbeResult(LOOPBACK_V4, Bypass::None, ProbeResult::Delivered);
}

TEST_P(KillswitchMode, HardLeftoversCleanedUp)
{
    int leftovers = 0;
    {
        auto hard = m_env.create(LIBXTUN_KILLSWITCH_MODE_HARD);
        ASSERT_NE(hard, nullptr);
        leftovers = m_env.ruleCount();
        ASSERT_GT(leftovers, 0);
    }

    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);
    EXPECT_EQ(m_env.ruleCount(), GetParam() == LIBXTUN_KILLSWITCH_MODE_DISABLED ? 0 : leftovers)
            << "the leftovers piled up";
}

TEST_P(KillswitchMode, UpdatingTwiceChangesNothing)
{
    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);
    const int installed = m_env.ruleCount();

    EXPECT_EQ(m_env.update(*killswitch), LIBXTUN_OK);
    EXPECT_EQ(m_env.ruleCount(), installed) << "updating again changed the rules";
}

TEST_P(KillswitchMode, DestructionHonoursPersistence)
{
    int installed = 0;
    {
        auto killswitch = m_env.create(GetParam());
        ASSERT_NE(killswitch, nullptr);
        installed = m_env.ruleCount();
        ASSERT_EQ(installed > 0, GetParam() != LIBXTUN_KILLSWITCH_MODE_DISABLED);
    }
    EXPECT_EQ(m_env.ruleCount(), persistent(GetParam()) ? installed : 0);
    expectProbeResult(TEST_NET_V4, Bypass::None, persistent(GetParam()) ? ProbeResult::Blocked : ProbeResult::Delivered);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchMode, testing::ValuesIn(libxtun::test::allKillswitchModes()),
                         [](const auto &info) { return modeName(info.param); });

class KillswitchTunnel : public libxtun::test::KillswitchTest,
                         public testing::WithParamInterface<std::tuple<libxtun_killswitch_mode, test::Setup>>
{
};

TEST_P(KillswitchTunnel, FullLifecycle)
{
    auto &[mode, setup] = GetParam();
    [[maybe_unused]] const auto srv = setup.createServer("server");

    libxtun::test::TunOpts opts;
    opts.killswitchMode(mode);

    libxtun::test::Logger log("client");

    libxtun_tunnel tun {};
    ASSERT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxy {};
    setup.wrapper->wrapProxy(proxy);
    log.wrapProxy(proxy);
    ASSERT_EQ(libxtun_proxy_new(&proxy, setup.proto, setup.clientA.c_str()), LIBXTUN_OK);
    ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    expectProbeResult(TEST_NET_V4, Bypass::None, ProbeResult::Delivered, "with the proxy attached");
    expectProbeResult(TEST_NET_V6, Bypass::None, probeResultFor(mode), "with the proxy attached");
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "with the proxy attached");
    expectProbeResult(TEST_NET_V6, Bypass::Proxy, ProbeResult::Delivered, "with the proxy attached");

    libxtun_tunnel_detach_proxy(&tun, &proxy);
    libxtun_proxy_free(&proxy);

    expectProbeResult(TEST_NET_V4, Bypass::None, probeResultFor(mode), "after the proxy detached");
    expectProbeResult(TEST_NET_V6, Bypass::None, probeResultFor(mode), "after the proxy detached");
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "after the proxy detached");
    expectProbeResult(TEST_NET_V6, Bypass::Proxy, ProbeResult::Delivered, "after the proxy detached");

    libxtun_tunnel_free(&tun);

    expectProbeResult(TEST_NET_V4, Bypass::None, persistent(mode) ? ProbeResult::Blocked : ProbeResult::Delivered,
                      "after the tunnel was freed");
    expectProbeResult(TEST_NET_V6, Bypass::None, persistent(mode) ? ProbeResult::Blocked : ProbeResult::Delivered,
                      "after the tunnel was freed");
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "after the tunnel was freed");
    expectProbeResult(TEST_NET_V6, Bypass::Proxy, ProbeResult::Delivered, "after the tunnel was freed");
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchTunnel,
                         testing::Combine(testing::ValuesIn(libxtun::test::allKillswitchModes()),
                                          testing::ValuesIn(test::SetupBuilder().withRoutes({ "0.0.0.0/0" }).build())),
                         [](const auto &info) {
                             const auto mode = std::get<0>(info.param);
                             const auto &setup = std::get<1>(info.param);
                             return modeName(mode) + "_" + setup.name;
                         });
