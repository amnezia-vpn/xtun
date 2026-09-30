#include "killswitch.h"
#include "mock/memserver.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/log.h"
#include "util/socket.h"
#include "xtun.h"

#include <memory>
#include <optional>
#include <string>

#include "gtest/gtest.h"

#if defined(__linux__) && !defined(__ANDROID__)
    #include "test_killswitch_linux.cpp"
#else
namespace libxtun::test
{
    KillswitchEnv::KillswitchEnv() : m_skipReason("not implemented on this platform yet")
    {
    }

    KillswitchEnv::~KillswitchEnv() = default;

    int KillswitchEnv::ruleCount() const
    {
        return 0;
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const std::string &, Bypass) const
    {
        return std::nullopt;
    }
}
#endif

namespace libxtun::test
{
    std::unique_ptr<Killswitch> KillswitchEnv::create(libxtun_killswitch_mode mode) const
    {
        std::unique_ptr<Killswitch> killswitch = Killswitch::create(mode);
        if (killswitch == nullptr) {
            ADD_FAILURE() << "Killswitch::create returned nothing";
            return nullptr;
        }
        if (const libxtun_error rc = killswitch->update(m_ifIndex, m_ifName); rc != LIBXTUN_OK) {
            ADD_FAILURE() << "Killswitch::update failed with " << rc << " error code";
            return nullptr;
        }
        return killswitch;
    }
}

namespace
{
    std::string modeName(const testing::TestParamInfo<libxtun_killswitch_mode> &info)
    {
        switch (info.param) {
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
protected:
    [[nodiscard]] static ProbeResult probeResultFor(libxtun_killswitch_mode mode) noexcept
    {
        return mode == LIBXTUN_KILLSWITCH_MODE_DISABLED ? ProbeResult::Delivered : ProbeResult::Blocked;
    }
    [[nodiscard]] static bool persistent(libxtun_killswitch_mode mode) noexcept
    {
        return mode == LIBXTUN_KILLSWITCH_MODE_HARD;
    }
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

TEST_P(KillswitchMode, ArmingTwiceAddsNothing)
{
    auto first = m_env.create(GetParam());
    ASSERT_NE(first, nullptr);
    const int afterFirst = m_env.ruleCount();

    auto second = m_env.create(GetParam());
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(m_env.ruleCount(), afterFirst) << "arming again added rules";
    expectProbeResult(TEST_NET_V4, Bypass::None, probeResultFor(GetParam()));
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

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchMode, testing::ValuesIn(libxtun::test::allKillswitchModes()), modeName);

class KillswitchTunnel : public KillswitchMode
{
};

TEST_P(KillswitchTunnel, FullLifecycle)
{
    const auto confs = libxtun::test::ConfpairBuilder().withRoutes({ "0.0.0.0/0" }).buildAwg();

    libxtun::test::TunOpts opts;
    opts.killswitchMode(GetParam());

    libxtun::test::Logger log("client");
    libxtun::test::SockBindRemover bindRemover;
    libxtun::test::MemServer srv("server", confs.proto, confs.server.c_str());

    libxtun_tunnel tun {};
    ASSERT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);

    libxtun_proxy proxy {};
    bindRemover.wrapProxy(proxy);
    log.wrapProxy(proxy);
    ASSERT_EQ(libxtun_proxy_new(&proxy, confs.proto, confs.clientA.c_str()), LIBXTUN_OK);
    ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    expectProbeResult(TEST_NET_V4, Bypass::None, ProbeResult::Delivered, "with the proxy attached");
    expectProbeResult(TEST_NET_V6, Bypass::None, probeResultFor(GetParam()), "with the proxy attached");
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "with the proxy attached");
    expectProbeResult(TEST_NET_V6, Bypass::Proxy, ProbeResult::Delivered, "with the proxy attached");

    libxtun_tunnel_detach_proxy(&tun, &proxy);
    libxtun_proxy_free(&proxy);

    expectProbeResult(TEST_NET_V4, Bypass::None, probeResultFor(GetParam()), "after the proxy detached");
    expectProbeResult(TEST_NET_V6, Bypass::None, probeResultFor(GetParam()), "after the proxy detached");
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "after the proxy detached");
    expectProbeResult(TEST_NET_V6, Bypass::Proxy, ProbeResult::Delivered, "after the proxy detached");

    libxtun_tunnel_free(&tun);

    expectProbeResult(TEST_NET_V4, Bypass::None, persistent(GetParam()) ? ProbeResult::Blocked : ProbeResult::Delivered,
                      "after the tunnel was freed");
    expectProbeResult(TEST_NET_V6, Bypass::None, persistent(GetParam()) ? ProbeResult::Blocked : ProbeResult::Delivered,
                      "after the tunnel was freed");
    expectProbeResult(TEST_NET_V4, Bypass::Proxy, ProbeResult::Delivered, "after the tunnel was freed");
    expectProbeResult(TEST_NET_V6, Bypass::Proxy, ProbeResult::Delivered, "after the tunnel was freed");
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchTunnel, testing::ValuesIn(libxtun::test::allKillswitchModes()), modeName);
