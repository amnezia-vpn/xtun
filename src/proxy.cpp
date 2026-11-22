#include "proxy.h"
#include "proto/awg.h"
#include "proto/xray.h"
#include "util/cinterop.h"
#include "xtun.h"

#include <algorithm>
#include <memory>

namespace libxtun
{
    ProxyProfile Proxy::profile() const
    {
        ProxyProfile profile = buildProfile();

        const auto addOnce = [](std::vector<net::IpPrefix> &list, const net::IpPrefix &prefix) {
            if (std::ranges::find(list, prefix) == list.end()) {
                list.push_back(prefix);
            }
        };

        std::vector<net::IpPrefix> includeRoutes;
        for (const net::IpPrefix &configured : profile.routes) {
            const net::IpPrefix route = configured.network();
            if (m_includeRoutes.empty()) {
                addOnce(includeRoutes, route);
                continue;
            }
            for (const net::IpPrefix &listed : m_includeRoutes) {
                const net::IpPrefix prefix = listed.network();
                if (route.contains(prefix)) {
                    addOnce(includeRoutes, prefix);
                } else if (prefix.contains(route)) {
                    addOnce(includeRoutes, route);
                }
            }
        }

        std::erase_if(includeRoutes, [&](const net::IpPrefix &included) {
            return std::ranges::any_of(m_excludeRoutes,
                                       [&](const net::IpPrefix &listed) { return listed.network().contains(included); });
        });

        std::vector<net::IpPrefix> excludeRoutes;
        for (const net::IpPrefix &listed : m_excludeRoutes) {
            const net::IpPrefix prefix = listed.network();
            if (std::ranges::any_of(includeRoutes,
                                    [&](const net::IpPrefix &included) { return included.contains(prefix); })) {
                addOnce(excludeRoutes, prefix);
            }
        }

        profile.includeRoutes = std::move(includeRoutes);
        profile.excludeRoutes = std::move(excludeRoutes);
        return profile;
    }

    ResultXtun<std::unique_ptr<Proxy>> Proxy::create(libxtun_proxy_proto proto, const char *conf,
                                                     ClientCallbacks callbacks, const libxtun_proxy_opts *opts)
    {
        if (opts != nullptr && opts->size < sizeof(*opts)) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        auto includeRoutes = cinterop::parseListT<net::IpPrefix>(opts != nullptr ? opts->includeRoutes : nullptr);
        if (!includeRoutes) {
            return fail(includeRoutes.error());
        }
        auto excludeRoutes = cinterop::parseListT<net::IpPrefix>(opts != nullptr ? opts->excludeRoutes : nullptr);
        if (!excludeRoutes) {
            return fail(excludeRoutes.error());
        }

        ResultXtun<std::unique_ptr<Proxy>> proxy = fail(LIBXTUN_ERR_INVALID_ARGS);
        switch (proto) {
        case LIBXTUN_PROXY_PROTO_AWG: proxy = proto::Awg::create(conf, callbacks); break;
        case LIBXTUN_PROXY_PROTO_XRAY: proxy = proto::Xray::create(conf, callbacks); break;
        }
        if (!proxy) {
            return proxy;
        }

        Proxy &created = *proxy.value();
        created.m_includeRoutes = std::move(includeRoutes).value();
        created.m_excludeRoutes = std::move(excludeRoutes).value();
        if (created.m_includeRoutes.empty() && created.m_excludeRoutes.empty()) {
            return proxy;
        }
        if (created.profile().includeRoutes.empty()) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        return proxy;
    }

    Proxy::Proxy(ClientCallbacks callbacks) : m_callbacks(callbacks) {};

    Proxy::~Proxy()
    {
    }

    void Proxy::attachIo(TunnelIo *io)
    {
        m_io.assign(io);
    }

    void Proxy::publishStatus(libxtun_status status)
    {
        // TODO: log?
        if (m_callbacks.onStatus != nullptr) {
            m_callbacks.onStatus(status, m_callbacks.onStatusPriv);
        }
    }

    int Proxy::tunRead(void *b, int len)
    {
        return m_io.read({ static_cast<std::byte *>(b), static_cast<std::size_t>(len) });
    }

    int Proxy::tunWrite(void *b, int len)
    {
        return m_io.write({ static_cast<std::byte *>(b), static_cast<std::size_t>(len) });
    }

    int Proxy::tunMtu()
    {
        return m_io.mtu();
    }

    void Proxy::sockCb(int fd)
    {
        m_io.protectSocket(fd);

        if (m_callbacks.onSocket != nullptr) {
            m_callbacks.onSocket(fd, m_callbacks.onSocketPriv);
        }
    }

    void Proxy::emitLog(char *str)
    {
        if (m_callbacks.onLog != nullptr) {
            m_callbacks.onLog(str, m_callbacks.onLogPriv);
        }
    }
}

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf,
                      const struct libxtun_proxy_opts *opts)
{
    if (proxy == nullptr || conf == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    proxy->handle = nullptr;

    libxtun::ClientCallbacks callbacks { .onSocket = proxy->onsockspawn,
                                         .onSocketPriv = proxy->onsockspawn_priv,
                                         .onLog = proxy->loghandler,
                                         .onLogPriv = proxy->loghandler_priv,
                                         .onStatus = proxy->statushandler,
                                         .onStatusPriv = proxy->statushandler_priv };

    auto res = libxtun::Proxy::create(proto, conf, callbacks, opts);
    if (!res)
        return res.error();

    proxy->handle = res.value().release();
    return LIBXTUN_OK;
}

void libxtun_proxy_free(struct libxtun_proxy *proxy)
{
    if (proxy == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Proxy *>(proxy->handle);
    proxy->handle = nullptr;
}
