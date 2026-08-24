#include "proxy.h"
#include "tunnel.h"
#include "proto/awg.h"
#include <memory>

using namespace libxtun;

ResultXtun<std::unique_ptr<Proxy>> createProxy(enum libxtun_proxy_proto proto, const char *conf) {
    switch (proto) {
        case LIBXTUN_PROXY_PROTO_AWG:
            return libxtun::proto::Awg::create(conf);
        // case LIBXTUN_PROXY_PROTO_VLESS:
        default:
            return libxtun::fail(LIBXTUN_ERR_INVALID_ARGS);
    }
}

libxtun::Proxy::~Proxy() {
    if (m_tunnel != nullptr) {
        m_tunnel->detachProxy(this);
    }
}

void libxtun::Proxy::cancelIo() {
    if (m_tunnel != nullptr) {
        m_tunnel->cancelRead();
    }
}

void libxtun::Proxy::emitLog(const char *message) noexcept {
    if (m_callbacks.on_log != nullptr) {
        m_callbacks.on_log(message, m_callbacks.on_log_priv);
    }
}

void libxtun::Proxy::registerBypassSocket(int fd, int family) {
    if (m_tunnel != nullptr) {
        m_tunnel->registerBypassSocket(fd, family);
    }
    if (m_callbacks.on_socket != nullptr) {
        m_callbacks.on_socket(fd, m_callbacks.on_socket_priv);
    }
}

void libxtun::Proxy::bypassSocket(int fd, int family) {
    if (m_tunnel != nullptr) {
        m_tunnel->bypassSocket(fd, family);
    }
    if (m_callbacks.on_socket != nullptr) {
        m_callbacks.on_socket(fd, m_callbacks.on_socket_priv);
    }
}

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf) {
    if (proxy == nullptr || conf == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    proxy->handle = nullptr;

    auto res = createProxy(proto, conf);
    if (!res)
        return res.error();

    auto obj = std::move(res.value());
    obj->bind(ClientCallbacks{proxy->onsockspawn, proxy->onsockspawn_priv,
                              proxy->loghandler, proxy->loghandler_priv});


    proxy->handle = obj.release();
    return LIBXTUN_OK;
}

void libxtun_proxy_free(struct libxtun_proxy *proxy) {
    if (proxy == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Proxy *>(proxy->handle);
    proxy->handle = nullptr;
}

