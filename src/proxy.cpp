#include "proxy.h"
#include "proto/awg.h"
#include "xtun.h"

#include <memory>

namespace libxtun
{
    ResultXtun<std::unique_ptr<Proxy>> Proxy::create(libxtun_proxy_proto proto, const char *conf,
                                                     ClientCallbacks callbacks)
    {
        switch (proto) {
        case LIBXTUN_PROXY_PROTO_AWG: return proto::Awg::create(conf, callbacks);
        case LIBXTUN_PROXY_PROTO_XRAY: return fail(LIBXTUN_ERR_UNSUPPORTED);
        default: return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
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

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf)
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

    auto res = libxtun::Proxy::create(proto, conf, callbacks);
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
