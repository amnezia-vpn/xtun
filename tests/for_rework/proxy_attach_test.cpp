#include "fake_tun_device.h"
#include "proxy.h"
#include "tunnel.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{

    struct RecordingProxy : libxtun::Proxy
    {
        int startCalls = 0;
        int stopCalls = 0;
        int startResult = LIBXTUN_OK;
        libxtun::TunnelIo *io = nullptr;
        std::vector<libxtun::ProxyEvent> events;

        const char *name() override
        {
            return "recording";
        }

        int start(libxtun::TunnelIo &i) override
        {
            ++startCalls;
            io = &i;
            return startResult;
        }

        void event(libxtun::ProxyEvent ev) override
        {
            events.push_back(ev);
        }

        void stop() override
        {
            ++stopCalls;
        }

        std::vector<std::string> proxyRoutes;
        libxtun::ProxyProfile profile() const override
        {
            return { proxyRoutes, {}, {} };
        }

        void log(const char *message)
        {
            emitLog(message);
        }
        void status(int value)
        {
            publishStatus(value);
        }
    };

    struct LogSpy
    {
        static std::vector<std::string> g_lines;
        static void *g_priv;

        static void handler(const char *message, void *p)
        {
            g_lines.emplace_back(message);
            g_priv = p;
        }

        static void reset()
        {
            g_lines.clear();
            g_priv = nullptr;
        }
    };

    std::vector<std::string> LogSpy::g_lines;
    void *LogSpy::g_priv = nullptr;

    struct StatusSpy
    {
        static std::vector<int> g_values;
        static void *g_priv;

        static void handler(int status, void *p)
        {
            g_values.push_back(status);
            g_priv = p;
        }

        static void reset()
        {
            g_values.clear();
            g_priv = nullptr;
        }
    };

    std::vector<int> StatusSpy::g_values;
    void *StatusSpy::g_priv = nullptr;

    constexpr const char *AWG_CONF = "[Interface]\n"
                                     "PrivateKey = QMLo1B9mJ0xmz3aQ6QZQZQZQZQZQZQZQZQZQZQZQZFo=\n"
                                     "Jc = 4\n";

    libxtun_tunnel_opts defaultOpts()
    {
        libxtun_tunnel_opts opts {};
        opts.size = sizeof(opts);
        opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        return opts;
    }

} // namespace

TEST(ProxyAttach, RejectsNullProxy)
{
    libxtun_tunnel_opts opts = defaultOpts();
    libxtun::Tunnel tunnel(opts);

    EXPECT_EQ(tunnel.attachProxy(nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ProxyAttach, StartsProxyWithTunnelIo)
{
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = defaultOpts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(proxy.startCalls, 1);
    EXPECT_NE(proxy.io, nullptr);
}

TEST(ProxyAttach, IoIsBoundToTheTunnelDevice)
{
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = defaultOpts();
    auto device = std::make_unique<FakeTunDevice>(1280);
    libxtun::Tunnel tunnel(opts, std::move(device));
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_NE(proxy.io, nullptr);

    EXPECT_EQ(proxy.io->mtu(), 1280);

    std::array<std::byte, 4> buf {};
    EXPECT_EQ(proxy.io->read(buf), libxtun::IO_FATAL);
    EXPECT_EQ(proxy.io->write(buf), libxtun::IO_FATAL);
}

TEST(ProxyAttach, FailedStartLeavesProxyDetached)
{
    RecordingProxy proxy;
    proxy.startResult = LIBXTUN_ERR_INVALID_ARGS;

    {
        libxtun_tunnel_opts opts = defaultOpts();
        libxtun::Tunnel tunnel(opts);
        EXPECT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_ERR_INVALID_ARGS);
    }

    EXPECT_EQ(proxy.startCalls, 1);
    EXPECT_EQ(proxy.stopCalls, 0);
}

TEST(ProxyAttach, ProxyDestroyedFirstDetachesItself)
{
    libxtun_tunnel_opts opts = defaultOpts();
    libxtun::Tunnel tunnel(opts);

    {
        RecordingProxy gone;
        ASSERT_EQ(tunnel.attachProxy(&gone), LIBXTUN_OK);
    }

    RecordingProxy fresh;
    EXPECT_EQ(tunnel.attachProxy(&fresh), LIBXTUN_OK);
    EXPECT_EQ(fresh.startCalls, 1);
}

TEST(ProxyAttach, RejectsReattachingSameProxy)
{
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = defaultOpts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(proxy.startCalls, 1);
}

TEST(ProxyAttach, AttachingAnotherProxyReplaces)
{
    RecordingProxy proxy;
    RecordingProxy other;
    libxtun_tunnel_opts opts = defaultOpts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.attachProxy(&other), LIBXTUN_OK);

    EXPECT_EQ(proxy.stopCalls, 1);
    EXPECT_EQ(other.startCalls, 1);
}

TEST(ProxyAttach, StopsProxyOnTunnelDestruction)
{
    RecordingProxy proxy;

    {
        libxtun_tunnel_opts opts = defaultOpts();
        libxtun::Tunnel tunnel(opts);
        ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
        EXPECT_EQ(proxy.stopCalls, 0);
    }

    EXPECT_EQ(proxy.stopCalls, 1);
}

TEST(AttachProxyC, RejectsNullArgs)
{
    libxtun_tunnel tun {};
    libxtun_proxy proxy {};
    RecordingProxy obj;

    tun.handle = nullptr;
    proxy.handle = &obj;
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(nullptr, &proxy), LIBXTUN_ERR_INVALID_ARGS);

    libxtun::Tunnel tunnel(defaultOpts());
    tun.handle = &tunnel;
    proxy.handle = nullptr;
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(AttachProxyC, AttachesThroughHandles)
{
    RecordingProxy obj;
    libxtun::Tunnel tunnel(defaultOpts());

    libxtun_tunnel tun {};
    tun.handle = &tunnel;
    libxtun_proxy proxy {};
    proxy.handle = &obj;

    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);
    EXPECT_EQ(obj.startCalls, 1);
}

TEST(ProxyAttach, EachProxyGetsItsOwnMeteredIo)
{
    RecordingProxy first;
    RecordingProxy second;
    libxtun_tunnel_opts opts = defaultOpts();
    libxtun::Tunnel one(opts);
    libxtun::Tunnel two(opts);

    ASSERT_EQ(one.attachProxy(&first), LIBXTUN_OK);
    ASSERT_EQ(two.attachProxy(&second), LIBXTUN_OK);

    ASSERT_NE(first.io, nullptr);
    ASSERT_NE(second.io, nullptr);
    EXPECT_NE(first.io, second.io) << "the two proxies share one monitored io";
}

TEST(ProxyAttach, DetachedProxyCanBeAttachedAgain)
{
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = defaultOpts();
    auto nextDevice = std::make_unique<FakeTunDevice>(1400);
    libxtun::Tunnel next(opts, std::move(nextDevice));

    {
        auto goneDevice = std::make_unique<FakeTunDevice>(1200);
        libxtun::Tunnel gone(opts, std::move(goneDevice));
        ASSERT_EQ(gone.attachProxy(&proxy), LIBXTUN_OK);
    }

    ASSERT_EQ(proxy.stopCalls, 1) << "the tunnel went away without closing the attachment";
    ASSERT_EQ(next.attachProxy(&proxy), LIBXTUN_OK) << "the detached proxy still looks attached";

    EXPECT_EQ(proxy.startCalls, 2);
    EXPECT_NE(proxy.io, nullptr);
    EXPECT_EQ(proxy.io->mtu(), 1400);
}

TEST(ProxyNew, RejectsBadArgs)
{
    libxtun_proxy proxy {};

    EXPECT_EQ(libxtun_proxy_new(nullptr, LIBXTUN_PROXY_PROTO_AWG, ""), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, nullptr), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_proxy_new(&proxy, static_cast<libxtun_proxy_proto>(LIBXTUN_PROXY_PROTO_LAST + 1), ""),
              LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_proxy_new(&proxy, static_cast<libxtun_proxy_proto>(0), ""), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ProxyCallbacks, LogReachesTheClientPriv)
{
    LogSpy::reset();

    int cookie = 0;
    libxtun_proxy cproxy {};
    cproxy.loghandler = &LogSpy::handler;
    cproxy.loghandler_priv = &cookie;

    RecordingProxy proxy;
    proxy.bind(libxtun::ClientCallbacks { .onSocket = cproxy.onsockspawn,
                                          .onSocketPriv = cproxy.onsockspawn_priv,
                                          .onLog = cproxy.loghandler,
                                          .onLogPriv = cproxy.loghandler_priv });
    proxy.log("hello");

    ASSERT_EQ(LogSpy::g_lines.size(), 1u);
    EXPECT_EQ(LogSpy::g_lines[0], "hello");
    EXPECT_EQ(LogSpy::g_priv, static_cast<void *>(&cookie));
    EXPECT_NE(LogSpy::g_priv, static_cast<void *>(&cproxy));
}

TEST(ProxyCallbacks, LogSurvivesTheCallerStructBeingOverwritten)
{
    LogSpy::reset();

    int cookie = 0;
    libxtun_proxy cproxy {};
    cproxy.loghandler = &LogSpy::handler;
    cproxy.loghandler_priv = &cookie;

    RecordingProxy proxy;
    proxy.bind(libxtun::ClientCallbacks { .onSocket = cproxy.onsockspawn,
                                          .onSocketPriv = cproxy.onsockspawn_priv,
                                          .onLog = cproxy.loghandler,
                                          .onLogPriv = cproxy.loghandler_priv });
    std::memset(&cproxy, 0, sizeof(cproxy));
    proxy.log("after");

    ASSERT_EQ(LogSpy::g_lines.size(), 1u);
    EXPECT_EQ(LogSpy::g_lines[0], "after");
    EXPECT_EQ(LogSpy::g_priv, static_cast<void *>(&cookie));
}

TEST(ProxyCallbacks, StatusReachesTheClientPriv)
{
    StatusSpy::reset();

    int cookie = 0;
    libxtun_proxy cproxy {};
    cproxy.statushandler = &StatusSpy::handler;
    cproxy.statushandler_priv = &cookie;

    RecordingProxy proxy;
    proxy.bind(libxtun::ClientCallbacks { .onSocket = cproxy.onsockspawn,
                                          .onSocketPriv = cproxy.onsockspawn_priv,
                                          .onLog = cproxy.loghandler,
                                          .onLogPriv = cproxy.loghandler_priv,
                                          .onStatus = cproxy.statushandler,
                                          .onStatusPriv = cproxy.statushandler_priv });
    proxy.status(LIBXTUN_STATUS_CONNECTED);

    ASSERT_EQ(StatusSpy::g_values.size(), 1u);
    EXPECT_EQ(StatusSpy::g_values[0], LIBXTUN_STATUS_CONNECTED);
    EXPECT_EQ(StatusSpy::g_priv, static_cast<void *>(&cookie));
}

TEST(ProxyCallbacks, UnboundProxyEmitsNothing)
{
    StatusSpy::reset();
    LogSpy::reset();

    RecordingProxy proxy;
    proxy.status(LIBXTUN_STATUS_DISCONNECTED);
    proxy.log("ignored");

    EXPECT_TRUE(StatusSpy::g_values.empty());
    EXPECT_TRUE(LogSpy::g_lines.empty());
}

TEST(ProxyNew, CreatesAwgFromValidConfig)
{
    libxtun_proxy proxy {};

    ASSERT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, AWG_CONF), LIBXTUN_OK);
    ASSERT_NE(proxy.handle, nullptr);
    EXPECT_STREQ(reinterpret_cast<libxtun::Proxy *>(proxy.handle)->name(), "awg");

    libxtun_proxy_free(&proxy);
    EXPECT_EQ(proxy.handle, nullptr);
}
