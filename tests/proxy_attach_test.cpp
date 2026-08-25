#include "proxy.h"
#include "tunnel.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct RecordingProxy : libxtun::Proxy {
    int startCalls = 0;
    int stopCalls = 0;
    int startResult = LIBXTUN_OK;
    libxtun::TunnelIo *io = nullptr;
    std::vector<libxtun::ProxyEvent> events;

    const char *name() override { return "recording"; }

    int start(libxtun::TunnelIo &i) override {
        ++startCalls;
        io = &i;
        return startResult;
    }

    void event(libxtun::ProxyEvent ev) override { events.push_back(ev); }

    void stop() override { ++stopCalls; }

    std::vector<std::string> proxyRoutes;
    libxtun::ProxyProfile profile() const override { return {proxyRoutes, {}, {}}; }

    void log(const char *message) { emitLog(message); }
};

struct LogSpy {
    static std::vector<std::string> lines;
    static void *priv;

    static void handler(const char *message, void *p) {
        lines.emplace_back(message);
        priv = p;
    }

    static void reset() {
        lines.clear();
        priv = nullptr;
    }
};

std::vector<std::string> LogSpy::lines;
void *LogSpy::priv = nullptr;

constexpr const char *kAwgConf =
    "[Interface]\n"
    "PrivateKey = QMLo1B9mJ0xmz3aQ6QZQZQZQZQZQZQZQZQZQZQZQZFo=\n"
    "Jc = 4\n";

libxtun_tunnel_opts default_opts() {
    libxtun_tunnel_opts opts{};
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
    return opts;
}

}  // namespace

TEST(ProxyAttach, RejectsNullProxy) {
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);

    EXPECT_EQ(tunnel.attachProxy(nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ProxyAttach, StartsProxyWithTunnelIo) {
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(proxy.startCalls, 1);
    EXPECT_NE(proxy.io, nullptr);
}

TEST(ProxyAttach, IoIsBoundToTheTunnel) {
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_NE(proxy.io, nullptr);

    EXPECT_EQ(proxy.io->mtu(), tunnel.currentMtu());

    std::array<std::byte, 4> buf{};
    EXPECT_EQ(proxy.io->read(buf), libxtun::kIoFatal);
    EXPECT_EQ(proxy.io->write(buf), libxtun::kIoFatal);
}

TEST(ProxyAttach, FailedStartLeavesProxyDetached) {
    RecordingProxy proxy;
    proxy.startResult = LIBXTUN_ERR_INVALID_ARGS;

    {
        libxtun_tunnel_opts opts = default_opts();
        libxtun::Tunnel tunnel(opts);
        EXPECT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_ERR_INVALID_ARGS);
    }

    EXPECT_EQ(proxy.startCalls, 1);
    EXPECT_EQ(proxy.stopCalls, 0);
}

TEST(ProxyAttach, ProxyDestroyedFirstDetachesItself) {
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);

    {
        RecordingProxy gone;
        ASSERT_EQ(tunnel.attachProxy(&gone), LIBXTUN_OK);
    }

    RecordingProxy fresh;
    EXPECT_EQ(tunnel.attachProxy(&fresh), LIBXTUN_OK);
    EXPECT_EQ(fresh.startCalls, 1);
}

TEST(ProxyAttach, RejectsReattachingSameProxy) {
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(proxy.startCalls, 1);
}

TEST(ProxyAttach, AttachingAnotherProxyReplaces) {
    RecordingProxy proxy;
    RecordingProxy other;
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.attachProxy(&other), LIBXTUN_OK);

    EXPECT_EQ(proxy.stopCalls, 1);
    EXPECT_EQ(other.startCalls, 1);
}

TEST(ProxyAttach, StopsProxyOnTunnelDestruction) {
    RecordingProxy proxy;

    {
        libxtun_tunnel_opts opts = default_opts();
        libxtun::Tunnel tunnel(opts);
        ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
        EXPECT_EQ(proxy.stopCalls, 0);
    }

    EXPECT_EQ(proxy.stopCalls, 1);
}

TEST(AttachProxyC, RejectsNullArgs) {
    libxtun_tunnel tun{};
    libxtun_proxy proxy{};
    RecordingProxy obj;

    tun.handle = nullptr;
    proxy.handle = &obj;
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(nullptr, &proxy), LIBXTUN_ERR_INVALID_ARGS);

    libxtun::Tunnel tunnel(default_opts());
    tun.handle = &tunnel;
    proxy.handle = nullptr;
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(AttachProxyC, AttachesThroughHandles) {
    RecordingProxy obj;
    libxtun::Tunnel tunnel(default_opts());

    libxtun_tunnel tun{};
    tun.handle = &tunnel;
    libxtun_proxy proxy{};
    proxy.handle = &obj;

    EXPECT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);
    EXPECT_EQ(obj.startCalls, 1);
}

TEST(ProxyNew, RejectsBadArgs) {
    libxtun_proxy proxy{};

    EXPECT_EQ(libxtun_proxy_new(nullptr, LIBXTUN_PROXY_PROTO_AWG, ""), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, nullptr), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_proxy_new(&proxy,
                                static_cast<libxtun_proxy_proto>(LIBXTUN_PROXY_PROTO_LAST + 1), ""),
              LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(libxtun_proxy_new(&proxy, static_cast<libxtun_proxy_proto>(0), ""),
              LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ProxyCallbacks, LogReachesTheClientPriv) {
    LogSpy::reset();

    int cookie = 0;
    libxtun_proxy cproxy{};
    cproxy.loghandler = &LogSpy::handler;
    cproxy.loghandler_priv = &cookie;

    RecordingProxy proxy;
    proxy.bind(libxtun::ClientCallbacks{cproxy.onsockspawn, cproxy.onsockspawn_priv,
                                        cproxy.loghandler, cproxy.loghandler_priv});
    proxy.log("hello");

    ASSERT_EQ(LogSpy::lines.size(), 1u);
    EXPECT_EQ(LogSpy::lines[0], "hello");
    EXPECT_EQ(LogSpy::priv, static_cast<void *>(&cookie));
    EXPECT_NE(LogSpy::priv, static_cast<void *>(&cproxy));
}

TEST(ProxyCallbacks, LogSurvivesTheCallerStructBeingOverwritten) {
    LogSpy::reset();

    int cookie = 0;
    libxtun_proxy cproxy{};
    cproxy.loghandler = &LogSpy::handler;
    cproxy.loghandler_priv = &cookie;

    RecordingProxy proxy;
    proxy.bind(libxtun::ClientCallbacks{cproxy.onsockspawn, cproxy.onsockspawn_priv,
                                        cproxy.loghandler, cproxy.loghandler_priv});
    std::memset(&cproxy, 0, sizeof(cproxy));
    proxy.log("after");

    ASSERT_EQ(LogSpy::lines.size(), 1u);
    EXPECT_EQ(LogSpy::lines[0], "after");
    EXPECT_EQ(LogSpy::priv, static_cast<void *>(&cookie));
}

TEST(ProxyNew, CreatesAwgFromValidConfig) {
    libxtun_proxy proxy{};

    ASSERT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, kAwgConf), LIBXTUN_OK);
    ASSERT_NE(proxy.handle, nullptr);
    EXPECT_STREQ(reinterpret_cast<libxtun::Proxy *>(proxy.handle)->name(), "awg");

    libxtun_proxy_free(&proxy);
    EXPECT_EQ(proxy.handle, nullptr);
}
