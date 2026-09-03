#include "tunnel.h"
#include "health/subsystem.h"

#include <atomic>
#include <cstring>

namespace
{
    std::vector<std::string> parseStrList(const char *const *list)
    {
        std::vector<std::string> out;
        if (list == nullptr) {
            return out;
        }
        while (*list != nullptr) {
            out.push_back(*list);
            ++list;
        }
        return out;
    }

}

namespace libxtun
{

    Tunnel::Tunnel(const libxtun_tunnel_opts &opts) : Tunnel(opts, createTunDevice())
    {
    }

    Tunnel::Tunnel(const libxtun_tunnel_opts &opts, std::unique_ptr<TunDevice> device)
        : m_dns(parseStrList(opts.dns)),
          m_dnsExceptions(parseStrList(opts.dns_exceptions)),
          m_killswitchMode(opts.killswitch_mode),
          m_ifAddrs(parseStrList(opts.if_addrs)),
          m_confMtu(opts.mtu),
          m_router(Router::create()),
          m_device(std::move(device)),
          m_health_settings(health::HealthSettings::fromSeconds(opts.health_seconds))
    {
    }

    Tunnel::~Tunnel()
    {
        m_device->stopMonitor();
        m_device->cancelRead();
        shutdownProxy(nullptr);
        if (m_router != nullptr) {
            m_router->revert();
        }
    }

    int Tunnel::openTun()
    {
        int rc = m_device->open();
        if (rc != LIBXTUN_OK) {
            return rc;
        }
        return completeDeviceSetup();
    }

    int Tunnel::adoptTun(int fd)
    {
        int rc = m_device->adoptFd(fd);
        if (rc != LIBXTUN_OK) {
            return rc;
        }
        return completeDeviceSetup();
    }

    int Tunnel::adoptTunByName(const char *name)
    {
        int rc = m_device->adoptName(name);
        if (rc != LIBXTUN_OK) {
            return rc;
        }
        return completeDeviceSetup();
    }

    int Tunnel::completeDeviceSetup()
    {
        // On Windows "ifIndex = -1" here means that Tunnel::adoptTunByName() was called and
        // we don't need to call m_router->configureInterface(),
        // otherwise it will reset mtu and metric for the previously configured interface
        const int ifIndex = m_device->ifIndex();
        if (ifIndex < 0) {
            return LIBXTUN_OK;
        }

        if (m_router != nullptr && m_router->configureInterface(m_device->name(), ifIndex, m_ifAddrs, m_confMtu) != 0) {
            return LIBXTUN_ERR_SYSTEM;
        }

        m_device->startMonitor(*this);

        return LIBXTUN_OK;
    }

    bool Tunnel::up() const
    {
        return m_device->up();
    }

    int Tunnel::attachProxy(Proxy *proxy)
    {
        if (proxy == nullptr || proxy->m_tunnel.load(std::memory_order_acquire) != nullptr) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        shutdownProxy(nullptr);

        m_device->resetReadCancellation();

        const ProxyProfile profile = proxy->profile();
        proxy->setInterface(m_device->name());
        TunnelIo &io = proxy->attach(*this, healthConfigFor(profile), *m_device);

        if (const int rc = proxy->start(io); rc != LIBXTUN_OK) {
            proxy->detach();
            return rc;
        }

        {
            std::lock_guard<std::mutex> lock(m_proxyMtx);
            m_proxy = proxy;
        }

        if (m_started && m_router != nullptr && m_router->setProxyRoutes(profile.routes) != 0) {
            shutdownProxy(proxy);
            return LIBXTUN_ERR_SYSTEM;
        }

        proxy->health()->start();
        return LIBXTUN_OK;
    }

    int Tunnel::start()
    {
        m_started = true;
        if (m_proxy != nullptr && m_router != nullptr) {
            if (m_router->setProxyRoutes(m_proxy->profile().routes) != 0) {
                m_router->revert();
                m_started = false;
                return LIBXTUN_ERR_SYSTEM;
            }
        }
        return LIBXTUN_OK;
    }

    void Tunnel::shutdownProxy(Proxy *expected) noexcept
    {
        Proxy *taken = takeProxy(expected);
        if (taken == nullptr) {
            return;
        }
        if (m_router != nullptr) {
            m_router->clearProxyRoutes();
        }
        taken->stop();
        taken->detach();
    }

    void Tunnel::detachProxy(Proxy *proxy) noexcept
    {
        if (takeProxy(proxy) != nullptr && m_router != nullptr) {
            m_router->clearProxyRoutes();
        }
    }

    Proxy *Tunnel::takeProxy(Proxy *expected) noexcept
    {
        std::lock_guard<std::mutex> lock(m_proxyMtx);
        if (m_proxy == nullptr || (expected != nullptr && m_proxy != expected)) {
            return nullptr;
        }
        m_bypass_sockets.clear();
        return std::exchange(m_proxy, nullptr);
    }

    health::HealthConfig Tunnel::healthConfigFor(const ProxyProfile &profile)
    {
        health::HealthConfig config;
        config.dns_servers = m_dns.empty() ? profile.dns_servers : m_dns;
        config.tunnel_addresses = m_ifAddrs.empty() ? profile.addresses : m_ifAddrs;
        config.tunnel_routes = profile.routes;
        config.probe_style = profile.probe_style;
        config.settings = m_health_settings;
        config.wake_read = [this] { wakeRead(); };
        return config;
    }

    void Tunnel::BypassSocketRegistry::add(Router &router, int fd, int family)
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_sockets[fd] = family;
        router.bypassSocket(fd, family);
    }

    void Tunnel::BypassSocketRegistry::rebind(Router &router)
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        for (const auto &[fd, family] : m_sockets) {
            router.bypassSocket(fd, family);
        }
    }

    void Tunnel::BypassSocketRegistry::clear()
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_sockets.clear();
    }

    void Tunnel::registerBypassSocket(int fd, int family)
    {
        if (m_router != nullptr) {
            m_bypass_sockets.add(*m_router, fd, family);
        }
    }

    void Tunnel::bypassSocket(int fd, int family)
    {
        if (m_router != nullptr) {
            m_router->bypassSocket(fd, family);
        }
    }

    void Tunnel::emit(Event ev)
    {
        if (m_onEvent) {
            m_onEvent(ev);
        }

        std::lock_guard<std::mutex> lock(m_proxyMtx);
        if (m_proxy == nullptr) {
            return;
        }

        switch (ev) {
        case Event::Up: m_proxy->event(ProxyEvent::Up); break;
        case Event::Down: m_proxy->event(ProxyEvent::Down); break;
        case Event::MtuUpdate: m_proxy->event(ProxyEvent::MtuUpdate); break;
        }
    }

    void Tunnel::onRouteChange()
    {
        if (m_router != nullptr && m_router->bypassChanged()) {
            m_bypass_sockets.rebind(*m_router);
        }

        std::lock_guard<std::mutex> lock(m_proxyMtx);
        if (m_proxy != nullptr) {
            m_proxy->health()->onNetworkChanged();
        }
    }

    void Tunnel::onLinkStateChanged(bool up)
    {
        emit(up ? Event::Up : Event::Down);
    }

    void Tunnel::onMtuChanged(int)
    {
        emit(Event::MtuUpdate);
    }

    void Tunnel::onRouteChanged()
    {
        onRouteChange();
    }

}

int libxtun_tunnel_new(struct libxtun_tunnel *tun, struct libxtun_tunnel_opts *opts)
{
    if (tun == nullptr || opts == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    if (opts->size < sizeof(*opts)) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    if (opts->killswitch_mode < LIBXTUN_KILLSWITCH_MODE_DISABLED || opts->killswitch_mode > LIBXTUN_KILLSWITCH_MODE_LAST) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *obj = new libxtun::Tunnel(*opts);

    int rc = obj->openTun();
    if (rc != LIBXTUN_OK) {
        delete obj;
        return rc;
    }

    tun->handle = obj;
    return LIBXTUN_OK;
}

int libxtun_tunnel_start(struct libxtun_tunnel *tun)
{
    if (tun == nullptr || tun->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }
    return reinterpret_cast<libxtun::Tunnel *>(tun->handle)->start();
}

int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, int fd)
{
    if (tun == nullptr || fd < 0) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    // The device was created and configured elsewhere, so no tunnel options
    // accompany it: empty DNS lists, killswitch disabled.
    struct libxtun_tunnel_opts opts;
    std::memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;

    auto *obj = new libxtun::Tunnel(opts);

    int rc = obj->adoptTun(fd);
    if (rc != LIBXTUN_OK) {
        delete obj;
        return rc;
    }

    tun->handle = obj;
    return LIBXTUN_OK;
}

int libxtun_tunnel_new_from_name(struct libxtun_tunnel *tun, const char *name)
{
    if (tun == nullptr || name == nullptr || name[0] == '\0') {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    struct libxtun_tunnel_opts opts;
    std::memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;

    auto *obj = new libxtun::Tunnel(opts);

    int rc = obj->adoptTunByName(name);
    if (rc != LIBXTUN_OK) {
        delete obj;
        return rc;
    }

    tun->handle = obj;
    return LIBXTUN_OK;
}

void libxtun_tunnel_free(struct libxtun_tunnel *tun)
{
    if (tun == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    tun->handle = nullptr;
}

int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    if (tun == nullptr || tun->handle == nullptr || proxy == nullptr || proxy->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    return obj->attachProxy(reinterpret_cast<libxtun::Proxy *>(proxy->handle));
}
