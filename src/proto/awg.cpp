#include "awg.h"

#include <libgoxtun.h>

#include <cstdlib>
#include <memory>
#include <variant>

namespace {

enum TunEvent {
    TunEventUp = 1,
    TunEventDown = 2,
    TunEventMtuUpdate = 4,
};

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

Awg::Awg(awg::Config conf)
    : m_conf(std::move(conf)) {}

Awg::~Awg() {
    stop();
}

ResultXtun<std::unique_ptr<Awg>> Awg::create(const std::string& str) {
    auto res = awg::Config::fromConf(str);
    if (!res)
        return fail(res.error());
    return std::make_unique<Awg>(std::move(res).value());
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

    m_conf.setFwmark(m_bypassToken);
    auto uapi = m_conf.toUapi();
    if (char *err = goxtun_awg_setconf(m_ctx, &uapi[0]); err != nullptr) {
        forwardLog(err, m_cproxy);
        goxtun_free(err);
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

void Awg::reapplyBypass() {
    if (m_ctx == nullptr) {
        return;
    }
    goxtun_awg_set_fwmark(m_ctx, m_bypassToken);
}

std::vector<std::string> Awg::routes() {
    std::vector<std::string> out;
    for (const auto &peer : m_conf.iface().peers) {
        for (const auto &ip : peer.allowed_ips) {
            out.push_back(ip.toUapi());
        }
    }
    return out;
}

}
}
