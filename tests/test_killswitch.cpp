#include "killswitch.h"
#include "proxy.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/log.h"
#include "util/os.h"
#include "util/status.h"
#include "xtun.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
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
}

namespace
{
    using libxtun::test::ConnectedSocket;
    using libxtun::test::Destination;
    using libxtun::test::ProbeResult;
    using libxtun::test::ScopedFd;
    using libxtun::test::Sender;
    using enum libxtun::test::ProbeResult;

    using libxtun::test::DNS_PORT;
    using libxtun::test::DNS_TLS_PORT;
    using libxtun::test::LOOPBACK_V4;
    using libxtun::test::PROBE_PORT;
    using libxtun::test::PROBE_TIMEOUT;

    using libxtun::test::ROUTED_HOST_V4;
    using libxtun::test::UNROUTED_HOST_V6;
    using libxtun::test::EXCLUDED_HOST_V4;

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
        std::uint16_t port = PROBE_PORT;
    };

    constexpr const char *LOCAL_SETUP = "awg_local";

    const Destination UNROUTED_HOST_V4 { "unrouted host v4", libxtun::test::probeAddress(1) };
    const Destination CONFIGURED_DNS { "configured DNS server", libxtun::test::probeAddress(0) };
    const Destination CONFIGURED_UNROUTED_DNS { "configured DNS server outside the routes", "192.0.2.53" };
    const Destination CONFIGURED_EXCLUDED_DNS { "configured DNS server inside an exclude", "192.0.2.55" };
    const Destination EXCEPTED_DNS { "excepted DNS server", "192.0.2.54" };
    const Destination UNCONFIGURED_DNS { "unconfigured DNS server", libxtun::test::probeAddress(1) };
    const std::string SPLIT_PREFIX = ROUTED_HOST_V4.host + "/32";
    const std::vector<std::string> FULL_ROUTES { "0.0.0.0/0" };
    const std::vector<std::string> SPLIT_ROUTES { SPLIT_PREFIX };

    const std::array FULL_TUNNEL_CASES {
        //                                                 before   up       no route detached freed
        // disabled
        std::array {
            ProbeCase { ROUTED_HOST_V4,   Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V6, Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { ROUTED_HOST_V4,   Sender::Proxy, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { CONFIGURED_DNS,   Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { EXCEPTED_DNS,     Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { UNCONFIGURED_DNS, Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { UNCONFIGURED_DNS, Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  }, DNS_TLS_PORT },
        },
        // soft
        std::array {
            ProbeCase { ROUTED_HOST_V4,   Sender::App,   { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V6, Sender::App,   { Uplink,  Blocked, Blocked, Uplink,  Uplink  } },
            ProbeCase { ROUTED_HOST_V4,   Sender::Proxy, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { CONFIGURED_DNS,   Sender::App,   { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { EXCEPTED_DNS,     Sender::App,   { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { UNCONFIGURED_DNS, Sender::App,   { Uplink,  Blocked, Blocked, Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { UNCONFIGURED_DNS, Sender::App,   { Uplink,  Blocked, Blocked, Uplink,  Uplink  }, DNS_TLS_PORT },
        },
        // hard
        std::array {
            ProbeCase { ROUTED_HOST_V4,   Sender::App,   { Uplink,  Tunnel,  Blocked, Blocked, Blocked } },
            ProbeCase { UNROUTED_HOST_V6, Sender::App,   { Uplink,  Blocked, Blocked, Blocked, Blocked } },
            ProbeCase { ROUTED_HOST_V4,   Sender::Proxy, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { CONFIGURED_DNS,   Sender::App,   { Uplink,  Tunnel,  Blocked, Blocked, Blocked }, DNS_PORT },
            ProbeCase { EXCEPTED_DNS,     Sender::App,   { Uplink,  Tunnel,  Blocked, Blocked, Blocked }, DNS_PORT },
            ProbeCase { UNCONFIGURED_DNS, Sender::App,   { Uplink,  Blocked, Blocked, Blocked, Blocked }, DNS_PORT },
            ProbeCase { UNCONFIGURED_DNS, Sender::App,   { Uplink,  Blocked, Blocked, Blocked, Blocked }, DNS_TLS_PORT },
        },
    };

    const std::array SPLIT_TUNNEL_CASES {
        //                                                        before   up       no route detached freed
        // disabled
        std::array {
            ProbeCase { ROUTED_HOST_V4,          Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V4,        Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V6,        Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { ROUTED_HOST_V4,          Sender::Proxy, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { CONFIGURED_DNS,          Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { CONFIGURED_DNS,          Sender::App,   { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  }, DNS_TLS_PORT },
            ProbeCase { CONFIGURED_UNROUTED_DNS, Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { EXCEPTED_DNS,            Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
        },
        // soft
        std::array {
            ProbeCase { ROUTED_HOST_V4,          Sender::App,   { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V4,        Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V6,        Sender::App,   { Uplink,  Blocked, Blocked, Uplink,  Uplink  } },
            ProbeCase { ROUTED_HOST_V4,          Sender::Proxy, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { CONFIGURED_DNS,          Sender::App,   { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { CONFIGURED_DNS,          Sender::App,   { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  }, DNS_TLS_PORT },
            ProbeCase { CONFIGURED_UNROUTED_DNS, Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { EXCEPTED_DNS,            Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
        },
        // hard
        std::array {
            ProbeCase { ROUTED_HOST_V4,          Sender::App,   { Uplink,  Tunnel,  Blocked, Blocked, Blocked } },
            ProbeCase { UNROUTED_HOST_V4,        Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNROUTED_HOST_V6,        Sender::App,   { Uplink,  Blocked, Blocked, Blocked, Blocked } },
            ProbeCase { ROUTED_HOST_V4,          Sender::Proxy, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { CONFIGURED_DNS,          Sender::App,   { Uplink,  Tunnel,  Blocked, Blocked, Blocked }, DNS_PORT },
            ProbeCase { CONFIGURED_DNS,          Sender::App,   { Uplink,  Tunnel,  Blocked, Blocked, Blocked }, DNS_TLS_PORT },
            ProbeCase { CONFIGURED_UNROUTED_DNS, Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { EXCEPTED_DNS,            Sender::App,   { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
        },
    };

    const std::array EXCLUDE_CASES {
        //                                                      before   up       no route detached freed
        // disabled
        std::array {
            ProbeCase { ROUTED_HOST_V4,          Sender::App, { Uplink,  Tunnel,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { EXCLUDED_HOST_V4,        Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNCONFIGURED_DNS,        Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { CONFIGURED_EXCLUDED_DNS, Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
        },
        // soft
        std::array {
            ProbeCase { ROUTED_HOST_V4,          Sender::App, { Uplink,  Tunnel,  Blocked, Uplink,  Uplink  } },
            ProbeCase { EXCLUDED_HOST_V4,        Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNCONFIGURED_DNS,        Sender::App, { Uplink,  Blocked, Blocked, Uplink,  Uplink  }, DNS_PORT },
            ProbeCase { CONFIGURED_EXCLUDED_DNS, Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
        },
        // hard
        std::array {
            ProbeCase { ROUTED_HOST_V4,          Sender::App, { Uplink,  Tunnel,  Blocked, Blocked, Blocked } },
            ProbeCase { EXCLUDED_HOST_V4,        Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  } },
            ProbeCase { UNCONFIGURED_DNS,        Sender::App, { Uplink,  Blocked, Blocked, Blocked, Blocked }, DNS_PORT },
            ProbeCase { CONFIGURED_EXCLUDED_DNS, Sender::App, { Uplink,  Uplink,  Uplink,  Uplink,  Uplink  }, DNS_PORT },
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
    const ConnectedSocket tcp = libxtun::test::tcpConnect(LOOPBACK_V4, loopback.port, PROBE_TIMEOUT);
    EXPECT_EQ(tcp.error, 0) << "loopback traffic was blocked";
}

TEST_P(KillswitchMode, HardLeftoversCleanedUp)
{
    int fresh = 0;
    {
        auto killswitch = m_env.create(GetParam());
        ASSERT_NE(killswitch, nullptr);
        fresh = m_env.ruleCount();
    }
    {
        auto hard = m_env.create(LIBXTUN_KILLSWITCH_MODE_HARD);
        ASSERT_NE(hard, nullptr);
        ASSERT_GT(m_env.ruleCount(), 0);
    }

    auto killswitch = m_env.create(GetParam());
    ASSERT_NE(killswitch, nullptr);
    EXPECT_EQ(m_env.ruleCount(), fresh) << "the leftovers piled up";
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
        ASSERT_EQ(killswitch->protect({ *net::IpPrefix::parse(FULL_ROUTES[0]) }, {}, {}), LIBXTUN_OK);
        installed = m_env.ruleCount();
        ASSERT_EQ(installed > 0, GetParam() != LIBXTUN_KILLSWITCH_MODE_DISABLED);
    }
    EXPECT_EQ(m_env.ruleCount(), persistent(GetParam()) ? installed : 0);
    expectProbeResult(ROUTED_HOST_V4, Sender::App, persistent(GetParam()) ? Blocked : Uplink);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchMode, testing::ValuesIn(libxtun::test::allKillswitchModes()),
                         [](const auto &info) { return modeName(info.param); });

class KillswitchProfile : public libxtun::test::KillswitchTest,
                          public testing::WithParamInterface<std::tuple<libxtun_killswitch_mode, test::Setup>>
{
protected:
    void checkLifecycle(const libxtun_proxy_opts *proxyOpts, std::span<const ProbeCase> allCases)
    {
        const auto &[mode, setup] = GetParam();
        [[maybe_unused]] const auto srv = setup.createServer("server");

        std::vector<ProbeCase> cases(allCases.begin(), allCases.end());
        if (setup.name != LOCAL_SETUP) {
            std::erase_if(cases, [](const ProbeCase &probeCase) {
                return probeCase.port == DNS_PORT || probeCase.port == DNS_TLS_PORT;
            });
        }

        libxtun::test::TunOpts tunOpts;
        tunOpts.killswitchMode(mode).dnsExceptions({ EXCEPTED_DNS.host });

        libxtun::test::Logger log("client");
        libxtun::test::StatusChecker status;

        const auto check = [&](TunnelState state) {
            for (const ProbeCase &probeCase : cases) {
                if (const std::optional<ProbeResult> result =
                            m_pathProbe.probe(probeCase.to, probeCase.sender, probeCase.port)) {
                    EXPECT_EQ(*result, probeCase.expected[state])
                            << probeCase.to.name << " port " << probeCase.port << ' ' << probeCase.sender << ", "
                            << TUNNEL_STATE_NAMES[state];
                }
            }
        };

        libxtun_tunnel tun {};
        ASSERT_EQ(libxtun_tunnel_new(&tun, &tunOpts.get()), LIBXTUN_OK);
        check(BEFORE_ATTACH);

        libxtun_proxy proxy {};
        setup.wrapper->wrapProxy(proxy);
        log.wrapProxy(proxy);
        status.wrapProxy(proxy);
        ASSERT_EQ(libxtun_proxy_new(&proxy, setup.proto, setup.clientA.c_str(), proxyOpts), LIBXTUN_OK);
        std::vector<std::string> routes;
        for (const net::IpPrefix &route : reinterpret_cast<Proxy *>(proxy.handle)->profile().includeRoutes) {
            routes.push_back(route.toString());
        }
        ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);
        ASSERT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, std::chrono::seconds(5)))
                << "the tunnel did not connect after attach";
        check(TUNNEL_UP);
        for (const ProbeCase &probeCase : cases) {
            if (probeCase.expected[TUNNEL_UP] == Tunnel) {
                const ConnectedSocket tcp =
                        libxtun::test::tcpConnect(probeCase.to.host, probeCase.port, PROBE_TIMEOUT);
                EXPECT_EQ(tcp.error, 0) << "no TCP reply through the tunnel from " << probeCase.to.name << " port "
                                        << probeCase.port;
            }
        }

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
    checkLifecycle(nullptr, FULL_TUNNEL_CASES[std::get<0>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchFullTunnel,
                         testing::Combine(testing::ValuesIn(libxtun::test::allKillswitchModes()),
                                          testing::ValuesIn(test::SetupBuilder()
                                                                   .withRoutes(FULL_ROUTES)
                                                                   .withDns({ CONFIGURED_DNS.host })
                                                                   .build())),
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
    checkLifecycle(nullptr, SPLIT_TUNNEL_CASES[std::get<0>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchSplitTunnel,
                         testing::Combine(testing::ValuesIn(libxtun::test::allKillswitchModes()),
                                          testing::ValuesIn(test::SetupBuilder()
                                                                   .withRoutes(SPLIT_ROUTES)
                                                                   .withDns({ CONFIGURED_DNS.host,
                                                                              CONFIGURED_UNROUTED_DNS.host })
                                                                   .build())),
                         [](const auto &info) {
                             const auto mode = std::get<0>(info.param);
                             const auto &setup = std::get<1>(info.param);
                             return modeName(mode) + "_" + setup.name;
                         });

class KillswitchExclude : public KillswitchProfile
{
};

TEST_P(KillswitchExclude, Lifecycle)
{
    const std::string excludedHost = EXCLUDED_HOST_V4.host + "/32";
    const std::string excludedDns = CONFIGURED_EXCLUDED_DNS.host + "/32";
    const char *excludes[] = { excludedHost.c_str(), excludedDns.c_str(), nullptr };
    const libxtun_proxy_opts excludeHosts { .size = sizeof(libxtun_proxy_opts), .excludeRoutes = excludes };
    checkLifecycle(&excludeHosts, EXCLUDE_CASES[std::get<0>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(Killswitch, KillswitchExclude,
                         testing::Combine(testing::ValuesIn(libxtun::test::allKillswitchModes()),
                                          testing::ValuesIn(test::SetupBuilder()
                                                                   .withRoutes(FULL_ROUTES)
                                                                   .withDns({ CONFIGURED_EXCLUDED_DNS.host })
                                                                   .build())),
                         [](const auto &info) {
                             const auto mode = std::get<0>(info.param);
                             const auto &setup = std::get<1>(info.param);
                             return modeName(mode) + "_" + setup.name;
                         });
