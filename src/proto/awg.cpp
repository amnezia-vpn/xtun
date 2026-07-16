#include "awg.h"

#include <awgconfig.h>
#include <libgoxtun.h>

#include <atomic>
#include <cstdlib>

namespace {

enum TunEvent {
    TunEventUp = 1,
    TunEventDown = 2,
    TunEventMtuUpdate = 4,
};

std::atomic<unsigned> g_instance{0};

int tunRead(void *b, int len, void *priv) {
    auto *io = static_cast<libxtun::ProxyIo *>(priv);
    return io->read(b, len);
}

int tunWrite(void *b, int len, void *priv) {
    auto *io = static_cast<libxtun::ProxyIo *>(priv);
    return io->write(b, len);
}

int tunMtu(void *priv) {
    auto *io = static_cast<libxtun::ProxyIo *>(priv);
    return io->mtu();
}

void forwardLog(char *str, void *priv) {
    auto *cproxy = static_cast<struct libxtun_proxy *>(priv);
    if (cproxy != nullptr && cproxy->loghandler != nullptr) {
        cproxy->loghandler(str, priv);
    }
}

}

namespace libxtun {
namespace proto {

Awg::Awg(const std::string &conf)
    : m_conf(conf), m_name("xtun" + std::to_string(g_instance.fetch_add(1))) {}

Awg::~Awg() {
    stop();
}

int Awg::start(const ProxyIo &io) {
    if (m_ctx != nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }
    if (!io.read || !io.write || !io.mtu) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    m_io = io;

    m_ctx = goxtun_awg_new(tunRead, tunWrite, tunMtu, &m_io, forwardLog, forwardLog, m_cproxy);
    if (m_ctx == nullptr) {
        return LIBXTUN_ERR_SYSTEM;
    }

    char *serveErr = goxtun_awg_serve_uapi(m_ctx, const_cast<char *>(m_name.c_str()));
    if (serveErr != nullptr) {
        forwardLog(serveErr, m_cproxy);
        free(serveErr);
        stop();
        return LIBXTUN_ERR_SYSTEM;
    }

    const char *err = nullptr;
    if (awg_apply_config(m_conf.c_str(), m_name.c_str(), &err) != 0) {
        if (err != nullptr) {
            forwardLog(const_cast<char *>(err), m_cproxy);
        }
        stop();
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    return LIBXTUN_OK;
}

void Awg::event(ProxyEvent ev) {
    if (m_ctx == nullptr) {
        return;
    }

    switch (ev) {
        case ProxyEvent::Up:
            goxtun_awg_event(m_ctx, TunEventUp);
            break;
        case ProxyEvent::Down:
            goxtun_awg_event(m_ctx, TunEventDown);
            break;
        case ProxyEvent::MtuUpdate:
            goxtun_awg_event(m_ctx, TunEventMtuUpdate);
            break;
    }
}

void Awg::stop() {
    if (m_ctx == nullptr) {
        return;
    }

    cancelIo();
    goxtun_awg_free(m_ctx);
    m_ctx = nullptr;
}

}
}
