#include "xtun.h"
#include "xtun.hpp"
#include <cassert>
#include <gtest/gtest.h>

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf)
{
    proxy->handle = new int { 0x7AFAFAFA };
    return 0;
}
void libxtun_proxy_free(struct libxtun_proxy *proxy)
{
    EXPECT_NE(proxy, nullptr) << "libxtun_proxy_free: proxy is null";
    EXPECT_NE(proxy->handle, nullptr) << "libxtun_proxy_free: proxy->handle is null";
    delete reinterpret_cast<int *>(proxy->handle);
}

struct FakeTunnel
{
    bool started = false;
    void *attachedProxy = nullptr;
};
int libxtun_tunnel_new(struct libxtun_tunnel *tun, const struct libxtun_tunnel_opts *opts)
{
    tun->handle = new FakeTunnel {};
    return 0;
}
int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, int fd)
{
    tun->handle = new FakeTunnel {};
    return 0;
}
int libxtun_tunnel_new_from_name(struct libxtun_tunnel *tun, const char *name)
{
    tun->handle = new FakeTunnel {};
    return 0;
}
int libxtun_tunnel_start(struct libxtun_tunnel *tun)
{
    EXPECT_NE(tun, nullptr) << "libxtun_tunnel_start: tun is null";
    EXPECT_NE(tun->handle, nullptr) << "libxtun_tunnel_start: tun->handle is null";
    if (tun == nullptr || tun->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *instance = reinterpret_cast<FakeTunnel *>(tun->handle);
    instance->started = true;
    return 0;
}
void libxtun_tunnel_free(struct libxtun_tunnel *tun)
{
    EXPECT_NE(tun, nullptr) << "libxtun_tunnel_free: tun is null";
    EXPECT_NE(tun->handle, nullptr) << "libxtun_tunnel_free: tun->handle is null";
    delete reinterpret_cast<FakeTunnel *>(tun->handle);
}
int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    EXPECT_NE(tun, nullptr) << "libxtun_tunnel_attach_proxy: tun is null";
    EXPECT_NE(proxy, nullptr) << "libxtun_tunnel_attach_proxy: proxy is null";
    EXPECT_NE(tun->handle, nullptr) << "libxtun_tunnel_attach_proxy: tun->handle is null";
    if (tun == nullptr || proxy == nullptr || tun->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *instance = reinterpret_cast<FakeTunnel *>(tun->handle);
    instance->attachedProxy = proxy;
    return 0;
}
void libxtun_tunnel_detach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    EXPECT_NE(tun, nullptr) << "libxtun_tunnel_detach_proxy: tun is null";
    EXPECT_NE(proxy, nullptr) << "libxtun_tunnel_detach_proxy: proxy is null";
    EXPECT_NE(tun->handle, nullptr) << "libxtun_tunnel_detach_proxy: tun->handle is null";

    auto *instance = reinterpret_cast<FakeTunnel *>(tun->handle);
    EXPECT_EQ(instance->attachedProxy, proxy);
    instance->attachedProxy = nullptr;
}

TEST(Fakextun, Lifecycle)
{
    auto resTun = xtun::TunnelBuilder().build();
    EXPECT_TRUE(std::holds_alternative<xtun::Tunnel>(resTun)) << "Tunnel build failed with " << std::get<int>(resTun);
    auto &tun = std::get<xtun::Tunnel>(resTun);

    auto resProxy = xtun::ProxyBuilder().build(LIBXTUN_PROXY_PROTO_AWG, "");
    EXPECT_TRUE(std::holds_alternative<xtun::Proxy>(resProxy)) << "Proxy build failed with " << std::get<int>(resProxy);
    auto &proxy = std::get<xtun::Proxy>(resProxy);

    EXPECT_EQ(tun.start(), 0);
    EXPECT_EQ(tun.attachProxy(proxy), 0);
    tun.detachProxy(proxy);
}
