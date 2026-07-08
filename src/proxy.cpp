#include "proxy.h"

namespace {

struct StubProxy : libxtun::Proxy {
    const char* name() override { return nullptr; }
};

}

libxtun::Proxy::~Proxy() {}

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf) {
    auto *obj = new StubProxy();

    proxy->handle = obj;
    return 0;
}

void libxtun_proxy_free(struct libxtun_proxy *proxy) {
    delete(reinterpret_cast<libxtun::Proxy*>(proxy->handle));
}

