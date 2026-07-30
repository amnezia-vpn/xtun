#include "proxy.h"
#include "tunnel.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

struct RecordingProxy : libxtun::Proxy {
    int startCalls = 0;
    int stopCalls = 0;
    int startResult = LIBXTUN_OK;
    bool haveIo = false;
    libxtun::ProxyIo io;
    std::vector<libxtun::ProxyEvent> events;

    const char *name() override { return "recording"; }

    int start(const libxtun::ProxyIo &i) override {
        ++startCalls;
        io = i;
        haveIo = true;
        return startResult;
    }

    void event(libxtun::ProxyEvent ev) override { events.push_back(ev); }

    void stop() override { ++stopCalls; }

    std::vector<std::string> proxyRoutes;
    std::vector<std::string> routes() override { return proxyRoutes; }
};

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
    ASSERT_TRUE(proxy.haveIo);
    EXPECT_TRUE(static_cast<bool>(proxy.io.read));
    EXPECT_TRUE(static_cast<bool>(proxy.io.write));
    EXPECT_TRUE(static_cast<bool>(proxy.io.mtu));
}

TEST(ProxyAttach, IoIsBoundToTheTunnel) {
    RecordingProxy proxy;
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(proxy.io.mtu(), tunnel.currentMtu());

    unsigned char buf[4] = {0};
    EXPECT_EQ(proxy.io.read(buf, sizeof(buf)), -1);
    EXPECT_EQ(proxy.io.write(buf, sizeof(buf)), -1);
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

TEST(ProxyAttach, RejectsAttachingTwice) {
    RecordingProxy proxy;
    RecordingProxy other;
    libxtun_tunnel_opts opts = default_opts();
    libxtun::Tunnel tunnel(opts);

    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(tunnel.attachProxy(&other), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(proxy.startCalls, 1);
    EXPECT_EQ(other.startCalls, 0);
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

TEST(ProxyNew, CreatesAwgFromValidConfig) {
    libxtun_proxy proxy{};

    ASSERT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, kAwgConf), LIBXTUN_OK);
    ASSERT_NE(proxy.handle, nullptr);
    EXPECT_STREQ(reinterpret_cast<libxtun::Proxy *>(proxy.handle)->name(), "awg");

    libxtun_proxy_free(&proxy);
    EXPECT_EQ(proxy.handle, nullptr);
}
