#include "awg.h"

#include <libgoxtun.h>

#include <cstdlib>
#include <memory>
#include <variant>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

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

    m_ctx = goxtun_awg_new(tunRead, tunWrite, tunMtu, &m_io, forwardLog, forwardLog, m_cproxy,
                           &Awg::sockCb, this);
    if (m_ctx == nullptr) {
        return LIBXTUN_ERR_SYSTEM;
    }

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

void Awg::sockCb(int fd, void *priv) {
    auto *self = static_cast<Awg *>(priv);
    std::lock_guard<std::mutex> lock(self->m_sockMtx);

    sockaddr_storage ss{};
#if defined(_WIN32)
    int len = sizeof(ss);
    if (::getsockname(static_cast<SOCKET>(fd), reinterpret_cast<sockaddr *>(&ss), &len) != 0) {
        return;
    }
#else
    socklen_t len = sizeof(ss);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &len) != 0) {
        return;
    }
#endif

    if (ss.ss_family == AF_INET6) {
        self->m_sock6 = fd;
    } else {
        self->m_sock4 = fd;
    }
    self->applyBypass(fd, ss.ss_family);
}

void Awg::applyBypass(int fd, int family) {
    if (m_bypassToken == 0) {
        return;
    }
#if defined(__linux__)
    (void)family;
    unsigned mark = m_bypassToken;
    ::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
#elif defined(__APPLE__)
    unsigned idx = m_bypassToken;
    if (family == AF_INET6) {
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
    } else {
        ::setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
    }
#elif defined(_WIN32)
    SOCKET s = static_cast<SOCKET>(fd);
    if (family == AF_INET6) {
        DWORD idx = m_bypassToken;
        ::setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<const char *>(&idx),
                     sizeof(idx));
    } else {
        DWORD idx = ::htonl(m_bypassToken);
        ::setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char *>(&idx),
                     sizeof(idx));
    }
#endif
}

void Awg::reapplyBypass() {
    std::lock_guard<std::mutex> lock(m_sockMtx);
    if (m_sock4 >= 0) {
        applyBypass(m_sock4, AF_INET);
    }
    if (m_sock6 >= 0) {
        applyBypass(m_sock6, AF_INET6);
    }
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
