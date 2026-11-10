#include "proxy.h"
#include "proto/awg.h"
#include "util/cinterop.h"
#include "xtun.h"

#include <algorithm>
#include <memory>

namespace libxtun
{
    std::optional<SplitRoutes> SplitRoutes::parse(const libxtun_proxy_opts *opts,
                                                  std::span<const net::IpPrefix> routes)
    {
        if (opts != nullptr && opts->size < sizeof(*opts)) {
            return std::nullopt;
        }
        auto includeList = cinterop::parseListT<net::IpPrefix>(opts != nullptr ? opts->includeRoutes : nullptr);
        auto excludeList = cinterop::parseListT<net::IpPrefix>(opts != nullptr ? opts->excludeRoutes : nullptr);
        if (!includeList || !excludeList) {
            return std::nullopt;
        }
        const std::vector<net::IpPrefix> &listedIncludes = includeList.value();
        const std::vector<net::IpPrefix> &listedExcludes = excludeList.value();

        const auto inside = [](const net::IpPrefix &inner, const net::IpPrefix &outer) {
            return outer.bits() <= inner.bits() && outer.contains(inner.address());
        };
        const auto addOnce = [](std::vector<net::IpPrefix> &list, const net::IpPrefix &prefix) {
            if (std::ranges::find(list, prefix) == list.end()) {
                list.push_back(prefix);
            }
        };

        SplitRoutes out;
        for (const net::IpPrefix &configured : routes) {
            const net::IpPrefix route = configured.network();
            if (listedIncludes.empty()) {
                addOnce(out.include, route);
                continue;
            }
            for (const net::IpPrefix &listed : listedIncludes) {
                const net::IpPrefix prefix = listed.network();
                if (inside(prefix, route)) {
                    addOnce(out.include, prefix);
                } else if (inside(route, prefix)) {
                    addOnce(out.include, route);
                }
            }
        }

        std::erase_if(out.include, [&](const net::IpPrefix &included) {
            return std::ranges::any_of(listedExcludes, [&](const net::IpPrefix &listed) {
                return inside(included, listed.network());
            });
        });
        if (out.include.empty() && (!listedIncludes.empty() || !listedExcludes.empty())) {
            return std::nullopt;
        }

        for (const net::IpPrefix &listed : listedExcludes) {
            const net::IpPrefix prefix = listed.network();
            if (std::ranges::any_of(out.include, [&](const net::IpPrefix &included) { return inside(prefix, included); })) {
                addOnce(out.exclude, prefix);
            }
        }
        return out;
    }

    ResultXtun<std::unique_ptr<Proxy>> Proxy::create(libxtun_proxy_proto proto, const char *conf,
                                                     ClientCallbacks callbacks,
                                                     const libxtun_proxy_opts *opts)
    {
        ResultXtun<std::unique_ptr<Proxy>> proxy = fail(LIBXTUN_ERR_INVALID_ARGS);
        switch (proto) {
        case LIBXTUN_PROXY_PROTO_AWG: proxy = proto::Awg::create(conf, callbacks); break;
        case LIBXTUN_PROXY_PROTO_XRAY: proxy = fail(LIBXTUN_ERR_UNSUPPORTED); break;
        default: break;
        }
        if (!proxy) {
            return proxy;
        }

        const ProxyProfile profile = proxy.value()->profile();
        auto split = SplitRoutes::parse(opts, profile.routes);
        if (!split) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        proxy.value()->m_splitRoutes = std::move(split).value();
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
