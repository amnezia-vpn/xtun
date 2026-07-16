#include "proxy.h"
#include "tunnel.h"
#include "proto/awg.h"

namespace {

int createProxy(enum libxtun_proxy_proto proto, const char *conf, libxtun::Proxy **out) {
    switch (proto) {
        case LIBXTUN_PROXY_PROTO_AWG:
            *out = new libxtun::proto::Awg(conf);
            return LIBXTUN_OK;
        case LIBXTUN_PROXY_PROTO_VLESS:
        default:
            return LIBXTUN_ERR_INVALID_ARGS;
    }
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

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf) {
    if (proxy == nullptr || conf == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    proxy->handle = nullptr;

    libxtun::Proxy *obj = nullptr;
    int rc = createProxy(proto, conf, &obj);
    if (rc != LIBXTUN_OK) {
        return rc;
    }

    obj->bind(proxy);

    proxy->handle = obj;
    return LIBXTUN_OK;
}

void libxtun_proxy_free(struct libxtun_proxy *proxy) {
    if (proxy == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Proxy *>(proxy->handle);
    proxy->handle = nullptr;
}

