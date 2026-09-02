#include "proxy.h"
#include "health/subsystem.h"
#include "tunnel.h"
#include "proto/awg.h"
#include <memory>
#include <optional>
#include <utility>

using namespace libxtun;

namespace {

[[nodiscard]] std::optional<libxtun_status> statusFor(health::ConnectionState state) noexcept {
    switch (state) {
        case health::ConnectionState::Connected:
            return LIBXTUN_STATUS_CONNECTED;
        case health::ConnectionState::NoNetwork:
            return LIBXTUN_STATUS_NO_NETWORK;
        case health::ConnectionState::Disconnected:
            return LIBXTUN_STATUS_DISCONNECTED;
        case health::ConnectionState::Unknown:
            return std::nullopt;
    }
    return std::nullopt;
}

}

ResultXtun<std::unique_ptr<Proxy>> createProxy(enum libxtun_proxy_proto proto, const char *conf) {
    switch (proto) {
        case LIBXTUN_PROXY_PROTO_AWG:
            return libxtun::proto::Awg::create(conf);
        // case LIBXTUN_PROXY_PROTO_VLESS:
        default:
            return libxtun::fail(LIBXTUN_ERR_INVALID_ARGS);
    }
}

libxtun::Proxy::Proxy() = default;

libxtun::Proxy::~Proxy() {
    if (Tunnel *tunnel = m_tunnel.load(std::memory_order_acquire)) {
        tunnel->detachProxy(this);
    }
    detach();
}

void libxtun::Proxy::cancelIo() {
    if (Tunnel *tunnel = m_tunnel.load(std::memory_order_acquire)) {
        tunnel->cancelRead();
    }
}

void libxtun::Proxy::emitLog(const char *message) noexcept {
    if (m_callbacks.on_log != nullptr) {
        m_callbacks.on_log(message, m_callbacks.on_log_priv);
    }
}

void libxtun::Proxy::emitStatus(int status) noexcept {
    if (m_callbacks.on_status != nullptr) {
        m_callbacks.on_status(status, m_callbacks.on_status_priv);
    }
}

void libxtun::Proxy::registerBypassSocket(int fd, int family) {
    if (Tunnel *tunnel = m_tunnel.load(std::memory_order_acquire)) {
        tunnel->registerBypassSocket(fd, family);
    }
    if (m_callbacks.on_socket != nullptr) {
        m_callbacks.on_socket(fd, m_callbacks.on_socket_priv);
    }
}

void libxtun::Proxy::bypassSocket(int fd, int family) {
    if (Tunnel *tunnel = m_tunnel.load(std::memory_order_acquire)) {
        tunnel->bypassSocket(fd, family);
    }
    if (m_callbacks.on_socket != nullptr) {
        m_callbacks.on_socket(fd, m_callbacks.on_socket_priv);
    }
}

void libxtun::Proxy::onConnectionState(health::ConnectionState state) noexcept {
    if (const auto status = statusFor(state)) {
        emitStatus(*status);
    }
    if (state != health::ConnectionState::Disconnected) {
        return;
    }

    if (m_health) {
        m_health->halt();
    }
    cancelIo();
    if (Tunnel *tunnel = m_tunnel.exchange(nullptr, std::memory_order_acq_rel)) {
        tunnel->detachProxy(this);
    }
    stop();
}

libxtun::TunnelIo &libxtun::Proxy::attach(Tunnel &tunnel, health::HealthConfig config,
                                          TunnelIo &device) {
    m_tunnel.store(&tunnel, std::memory_order_release);
    config.bind_socket = [this](int fd, int family) { bypassSocket(fd, family); };
    config.log = [this](const char *message) { emitLog(message); };

    health::HealthListener &listener = *this;
    m_health = std::make_unique<health::HealthSubsystem>(listener, std::move(config));
    return m_health->decorate(device);
}

void libxtun::Proxy::detach() noexcept {
    m_tunnel.store(nullptr, std::memory_order_release);
    m_health.reset();
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
    obj->bind(ClientCallbacks{.on_socket = proxy->onsockspawn,
                              .on_socket_priv = proxy->onsockspawn_priv,
                              .on_log = proxy->loghandler,
                              .on_log_priv = proxy->loghandler_priv,
                              .on_status = proxy->statushandler,
                              .on_status_priv = proxy->statushandler_priv});


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
