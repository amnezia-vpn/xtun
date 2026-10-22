#include "killswitch.h"
#include "mock/responder.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/log.h"
#include "util/os.h"
#include "util/status.h"
#include "xtun.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

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

    std::optional<ProbeResult> KillswitchEnv::probe(const Destination &to, Sender sender) const
    {
        if (sender != Sender::Forwarded) {
            return connect(to.host, PROBE_PORT, sender);
        }
        if (m_realEndpoint) {
            return std::nullopt;
        }

        const std::optional<net::IpAddress> destination = net::IpAddress::parse(to.host);
        if (!destination || destination->family() != AF_INET) {
            ADD_FAILURE() << "forwarded probes are IPv4 only, got " << to.host;
            return std::nullopt;
        }

        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            m_uplinkPackets.clear();
        }
        const std::uint16_t sport = randomPort();
        if (!injectSyn(*destination, sport)) {
            return std::nullopt;
        }
        return synSeenOnUplink(sport) ? ProbeResult::Uplink : ProbeResult::NotUplink;
    }

    std::vector<std::byte> KillswitchEnv::handleUplinkPacket(std::span<const std::byte> packet) const
    {
        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            m_uplinkPackets.emplace_back(packet.begin(), packet.end());
        }
        m_arrived.notify_all();
        return Responder::replyTcpSyn(packet);
    }

    bool KillswitchEnv::synSeenOnUplink(std::uint16_t sport) const
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_arrived.wait_for(lock, PROBE_TIMEOUT, [this, sport] {
            return std::ranges::any_of(m_uplinkPackets, [sport](const std::vector<std::byte> &packet) {
                return isForwardedSyn(packet, sport);
            });
        });
    }
}

namespace
{
    using libxtun::test::Destination;
    using libxtun::test::HIJACKED;
    using libxtun::test::INTERNET_V4;
    using libxtun::test::INTERNET_V6;
    using libxtun::test::LAN;
    using libxtun::test::LOOPBACK_V4;
    using libxtun::test::ProbeResult;
    using libxtun::test::ScopedFd;
    using libxtun::test::Sender;
    using enum libxtun::test::ProbeResult;

    struct LoopbackSocket
    {
        ScopedFd fd;
        std::uint16_t port = 0;
    };

    LoopbackSocket openLoopbackSocket()
    {
        ScopedFd sock(static_cast<int>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)));
        ::sockaddr_in address {};
        address.sin_family = AF_INET;
        ::inet_pton(AF_INET, LOOPBACK_V4, &address.sin_addr);
        ::socklen_t size = sizeof(address);
        if (!sock || ::bind(sock.get(), reinterpret_cast<::sockaddr *>(&address), sizeof(address)) != 0
            || ::listen(sock.get(), 1) != 0
            || ::getsockname(sock.get(), reinterpret_cast<::sockaddr *>(&address), &size) != 0) {
            return {};
        }
        return { std::move(sock), ntohs(address.sin_port) };
    }

    std::string modeName(libxtun_killswitch_mode mode)
    {
        switch (mode) {
        case LIBXTUN_KILLSWITCH_MODE_DISABLED: return "Disabled";
        case LIBXTUN_KILLSWITCH_MODE_SOFT: return "Soft";
        case LIBXTUN_KILLSWITCH_MODE_HARD: return "Hard";
        }
        return "Unknown";
    }

    enum TunnelState : std::size_t {
        BEFORE_ATTACH,
        TUNNEL_UP,
        ROUTES_LOST,
        DETACHED,
        FREED,
        TUNNEL_STATE_COUNT
    };

    constexpr std::array<const char *, TUNNEL_STATE_COUNT> TUNNEL_STATE_NAMES {
        "before attach", "with the tunnel up", "with the routes lost", "after detach", "after the tunnel was freed",
    };

    struct ProbeCase
    {
        Destination to;
        Sender sender;
        std::array<ProbeResult, TUNNEL_STATE_COUNT> expected;
    };

    const Destination SPLIT_DESTINATION { "split destination", libxtun::test::probeAddress(0) };
    const std::string SPLIT_PREFIX = libxtun::test::probeAddress(0) + "/32";
    const std::vector<std::string> FULL_ROUTES { "0.0.0.0/0" };
    const std::vector<std::string> SPLIT_ROUTES { SPLIT_PREFIX };

    const std::array FULL_PROFILE {
        //                                                before     up         no route   detached   freed
        // disabled
        std::array {
            ProbeCase { INTERNET_V4, Sender::App,       { Uplink,    Tunnel,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { INTERNET_V6, Sender::App,       { Uplink,    Uplink,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { LAN,         Sender::App,       { Uplink,    Uplink,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { HIJACKED,    Sender::App,       { Uplink,    Uplink,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { INTERNET_V4, Sender::Proxy,     { Uplink,    Uplink,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { INTERNET_V4, Sender::Forwarded, { Uplink,    NotUplink, Uplink,    Uplink,    Uplink    } },
        },
        // soft
        std::array {
            ProbeCase { INTERNET_V4, Sender::App,       { Blocked,   Tunnel,    Blocked,   Blocked,   Uplink    } },
            ProbeCase { INTERNET_V6, Sender::App,       { Blocked,   Blocked,   Blocked,   Blocked,   Uplink    } },
            ProbeCase { LAN,         Sender::App,       { Blocked,   Blocked,   Blocked,   Blocked,   Uplink    } },
            ProbeCase { HIJACKED,    Sender::App,       { Blocked,   Blocked,   Blocked,   Blocked,   Uplink    } },
            ProbeCase { INTERNET_V4, Sender::Proxy,     { Uplink,    Uplink,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { INTERNET_V4, Sender::Forwarded, { NotUplink, NotUplink, NotUplink, NotUplink, Uplink    } },
        },
        // hard
        std::array {
            ProbeCase { INTERNET_V4, Sender::App,       { Blocked,   Tunnel,    Blocked,   Blocked,   Blocked   } },
            ProbeCase { INTERNET_V6, Sender::App,       { Blocked,   Blocked,   Blocked,   Blocked,   Blocked   } },
            ProbeCase { LAN,         Sender::App,       { Blocked,   Blocked,   Blocked,   Blocked,   Blocked   } },
            ProbeCase { HIJACKED,    Sender::App,       { Blocked,   Blocked,   Blocked,   Blocked,   Blocked   } },
            ProbeCase { INTERNET_V4, Sender::Proxy,     { Uplink,    Uplink,    Uplink,    Uplink,    Uplink    } },
            ProbeCase { INTERNET_V4, Sender::Forwarded, { NotUplink, NotUplink, NotUplink, NotUplink, NotUplink } },
        },
    };

    const std::array SPLIT_PROFILE {
        //                                                before   up       no route detached freed
        // disabled
        std::array {
            ProbeCase { SPLIT_DESTINATION, Sender::App, { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { INTERNET_V4,       Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { INTERNET_V6,       Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { LAN,               Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
        },
        // soft
        std::array {
            ProbeCase { SPLIT_DESTINATION, Sender::App, { Blocked, Tunnel,  Blocked, Blocked, Uplink  } },
            ProbeCase { INTERNET_V4,       Sender::App, { Blocked, Uplink,  Uplink,  Blocked, Uplink  } },
            ProbeCase { INTERNET_V6,       Sender::App, { Blocked, Blocked, Blocked, Blocked, Uplink  } },
            ProbeCase { LAN,               Sender::App, { Blocked, Uplink,  Uplink,  Blocked, Uplink  } },
        },
        // hard
        std::array {
            ProbeCase { SPLIT_DESTINATION, Sender::App, { Blocked, Tunnel,  Blocked, Blocked, Blocked } },
            ProbeCase { INTERNET_V4,       Sender::App, { Blocked, Uplink,  Uplink,  Blocked, Blocked } },
            ProbeCase { INTERNET_V6,       Sender::App, { Blocked, Blocked, Blocked, Blocked, Blocked } },
            ProbeCase { LAN,               Sender::App, { Blocked, Uplink,  Uplink,  Blocked, Blocked } },
        },
    };
}

class KillswitchMode : public libxtun::test::KillswitchTest, public testing::WithParamInterface<libxtun_killswitch_mode>
{
};

TEST_P(KillswitchMode, LoopbackStaysUsable)
{
    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);

    const LoopbackSocket loopback = openLoopbackSocket();
    ASSERT_TRUE(loopback.fd) << "could not listen on " << LOOPBACK_V4;
    const std::optional<ProbeResult> result = m_env.connect(LOOPBACK_V4, loopback.port, Sender::App);
    ASSERT_TRUE(result);
    EXPECT_NE(*result, Blocked) << "loopback traffic was blocked";
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
    expectProbeResult(INTERNET_V4, Sender::App, persistent(GetParam()) ? Blocked : Uplink);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchMode, testing::ValuesIn(libxtun::test::allKillswitchModes()),
                         [](const auto &info) { return modeName(info.param); });

class KillswitchProfile : public libxtun::test::KillswitchTest,
                          public testing::WithParamInterface<std::tuple<libxtun_killswitch_mode, test::Setup>>
{
protected:
    KillswitchProfile() : KillswitchTest(std::get<1>(GetParam()).realEndpoint)
    {
    }

    void checkLifecycle(const std::vector<std::string> &routes, std::span<const ProbeCase> cases)
    {
        const auto &[mode, setup] = GetParam();
        [[maybe_unused]] const auto srv = setup.createServer("server");

        libxtun::test::TunOpts opts;
        opts.killswitchMode(mode);

        libxtun::test::Logger log("client");
        libxtun::test::StatusChecker status;

        const auto check = [&](TunnelState state) {
            for (const ProbeCase &probeCase : cases) {
                if (const std::optional<ProbeResult> result = m_env.probe(probeCase.to, probeCase.sender)) {
                    EXPECT_EQ(*result, probeCase.expected[state])
                            << probeCase.to.name << ' ' << probeCase.sender << ", " << TUNNEL_STATE_NAMES[state];
                }
            }
        };

        libxtun_tunnel tun {};
        ASSERT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_OK);
        check(BEFORE_ATTACH);

        libxtun_proxy proxy {};
        setup.wrapper->wrapProxy(proxy);
        log.wrapProxy(proxy);
        status.wrapProxy(proxy);
        ASSERT_EQ(libxtun_proxy_new(&proxy, setup.proto, setup.clientA.c_str()), LIBXTUN_OK);
        ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);
        ASSERT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, std::chrono::seconds(5)))
                << "the tunnel did not connect after attach";
        check(TUNNEL_UP);

        ASSERT_TRUE(m_env.removeTunnelRoutes(routes)) << "could not remove the tunnel's routes";
        check(ROUTES_LOST);

        libxtun_tunnel_detach_proxy(&tun, &proxy);
        libxtun_proxy_free(&proxy);
        check(DETACHED);

        libxtun_tunnel_free(&tun);
        check(FREED);
    }
};

class KillswitchFullTunnel : public KillswitchProfile
{
};

TEST_P(KillswitchFullTunnel, Lifecycle)
{
    checkLifecycle(FULL_ROUTES, FULL_PROFILE[std::get<0>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchFullTunnel,
                         testing::Combine(testing::ValuesIn(libxtun::test::allKillswitchModes()),
                                          testing::ValuesIn(test::SetupBuilder().withRoutes(FULL_ROUTES).build())),
                         [](const auto &info) {
                             const auto mode = std::get<0>(info.param);
                             const auto &setup = std::get<1>(info.param);
                             return modeName(mode) + "_" + setup.name;
                         });

class KillswitchSplitTunnel : public KillswitchProfile
{
};

TEST_P(KillswitchSplitTunnel, Lifecycle)
{
    checkLifecycle(SPLIT_ROUTES, SPLIT_PROFILE[std::get<0>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchSplitTunnel,
                         testing::Combine(testing::ValuesIn(libxtun::test::allKillswitchModes()),
                                          testing::ValuesIn(test::SetupBuilder().withRoutes(SPLIT_ROUTES).build())),
                         [](const auto &info) {
                             const auto mode = std::get<0>(info.param);
                             const auto &setup = std::get<1>(info.param);
                             return modeName(mode) + "_" + setup.name;
                         });
