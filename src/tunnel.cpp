#include "killswitch.h"
#include "net/ip.h"
#include "proxy.h"
#include "tun_device.h"
#include "tunnel.h"
#include "xtun.h"
#include <utility>

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
    namespace
    {
        ResultXtun<std::vector<net::IpAddress>> parseAddrList(const char *const *list)
        {
            std::vector<net::IpAddress> out;
            for (const std::string &text : parseStrList(list)) {
                const auto addr = net::IpAddress::parse(text);
                if (!addr) {
                    return fail(LIBXTUN_ERR_INVALID_ARGS);
                }
                out.push_back(*addr);
            }
            return out;
        }
    }

    Tunnel::~Tunnel()
    {
        if (m_proxy) {
            m_proxy->attachIo(nullptr);
        }
        m_device->stopMonitor();
        m_device->cancelRead();
        if (m_dns != nullptr) {
            m_dns->revert();
        }
        if (m_router != nullptr) {
            m_router->revert();
        }
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromOpts(const libxtun_tunnel_opts &opts)
    {
        auto dnsDefaults = parseAddrList(opts.dns);
        if (!dnsDefaults) {
            return fail(dnsDefaults.error());
        }
        const auto dnsExceptions = parseAddrList(opts.dns_exceptions);
        if (!dnsExceptions) {
            return fail(dnsExceptions.error());
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_dnsDefaults = std::move(dnsDefaults).value();
        tun->m_device = createTunDevice();
        tun->m_router = Router::create();
        tun->m_killswitch = Killswitch::create(opts.killswitch_mode, opts.macos_group);

        auto &dev = tun->m_device;
        auto &router = tun->m_router;
        auto &killswitch = tun->m_killswitch;

        if (auto rc = dev->open(); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        dev->startMonitor(*tun);

        const auto ifAddrs = parseStrList(opts.if_addrs);
        if (auto rc = router->configureInterface(dev->name(), dev->ifIndex(), ifAddrs, opts.mtu); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        if (auto rc = killswitch->update(dev->ifIndex(), dev->name())) {
            return fail(rc);
        }

        tun->m_dns = Dns::create(dev->ifIndex(), dev->name());

        // FIXME(cd-amn): add a handle in router to obtain these addrs, and remove this one completely
        for (const auto &ifAddr : ifAddrs) {
            if (auto prefix = net::IpPrefix::parse(ifAddr)) {
                tun->m_addrs.emplace_back(std::move(*prefix));
            }
        }

        return tun;
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromFd(int fd)
    {
        auto dev = createTunDevice();
        auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_DISABLED);
        if (auto rc = dev->adoptFd(fd); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_device = std::move(dev);
        tun->m_killswitch = std::move(killswitch);
        return tun;
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromName(const char *name)
    {
        auto dev = createTunDevice();
        auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_DISABLED);
        if (auto rc = dev->adoptName(name); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_device = std::move(dev);
        tun->m_killswitch = std::move(killswitch);
        return tun;
    }

    int Tunnel::attachProxy(Proxy *proxy)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (proxy == nullptr) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        ProxyProfile profile = proxy->profile();
        const std::vector<net::IpAddress> &resolvers = profile.dnsServers.empty() ? m_dnsDefaults : profile.dnsServers;

        if (m_killswitch != nullptr) {
            if (auto rc = m_killswitch->protect(profile.routes); rc != LIBXTUN_OK) {
                detachProxyLocked(m_proxy);
                if (m_dns != nullptr) {
                    m_dns->revert();
                }
                m_killswitch->protect({});
                return rc;
            }
        }

        if (m_proxy) {
            detachProxyLocked(m_proxy);
        }

        if (m_router != nullptr) {
            // TODO(cd-amn): use net::IpPrefix in routers
            std::vector<std::string> strRoutes;
            strRoutes.reserve(sizeof(profile.routes));
            for (const auto &route : profile.routes) {
                strRoutes.push_back(route.toString());
            }
            if (auto rc = m_router->setProxyRoutes(strRoutes); rc != LIBXTUN_OK) {
                // FIXME(cd-amn): we are reverting too much in here. Should be rollback() or similar
                m_router->revert();
                if (m_dns != nullptr) {
                    m_dns->revert();
                }
                if (m_killswitch != nullptr) {
                    m_killswitch->protect({});
                }
                return LIBXTUN_ERR_SYSTEM;
            }
        }

        if (m_dns != nullptr) {
            if (m_dns->apply(resolvers) != LIBXTUN_OK) {
                m_dns->revert();
                if (m_router != nullptr) {
                    m_router->clearProxyRoutes();
                }
                if (m_killswitch != nullptr) {
                    m_killswitch->protect({});
                }
                return LIBXTUN_ERR_DNS;
            }
        }

        m_device->resetReadCancellation();

        proxy->attachIo(this);
        proxy->event(m_device->up() ? ProxyEvent::Up : ProxyEvent::Down);
        m_proxy = proxy;

        return LIBXTUN_OK;
    }

    void Tunnel::detachProxy(Proxy *proxy)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (proxy == nullptr || m_proxy != proxy) {
            return;
        }

        if (m_dns != nullptr) {
            m_dns->revert();
        }
        detachProxyLocked(proxy);
        if (m_killswitch != nullptr) {
            m_killswitch->protect({});
        }
    }

    void Tunnel::detachProxyLocked(Proxy *proxy)
    {
        if (proxy == nullptr || m_proxy != proxy) {
            return;
        }

        if (m_router) {
            // FIXME(cd-amn): clear routes only for particular Proxy
            m_router->clearProxyRoutes();
        }

        // FIXME: this abstraction make sense for ONE to MANY model
        (void)proxy;

        m_proxy->event(ProxyEvent::Down);
        m_proxy->attachIo(nullptr);
        m_proxy = nullptr;
    }

    int Tunnel::start()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_started = true;
        // TODO(cd-amn): implement kick-off and suspend/shutdown based on metrics for the routes
        // The idea:
        // - All routes initialize with high metrics (system never use them until the raise)
        // - Calling start() sets all routes' metrics to the lower value
        // - So the traffic starts flowing
        //
        // This makes start() to respond almost instantly: interface is ready, and everything
        // is established, no further change required
        return LIBXTUN_OK;
    }

    void Tunnel::emit(Event ev)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_proxy == nullptr) {
            return;
        }

        switch (ev) {
        case Event::Up: m_proxy->event(ProxyEvent::Up); break;
        case Event::Down: m_proxy->event(ProxyEvent::Down); break;
        case Event::MtuUpdate: m_proxy->event(ProxyEvent::MtuUpdate); break;
        }
    }

    int Tunnel::read(std::span<std::byte> buf)
    {
        return m_device->read(buf);
    }

    int Tunnel::write(std::span<const std::byte> packet)
    {
        return m_device->write(packet);
    }

    void Tunnel::protectSocket(int fd)
    {
        if (m_router != nullptr) {
            m_router->protectSocket(fd);
        }
    }

    void Tunnel::wake()
    {
        m_device->wakeRead();
    }

    void Tunnel::halt()
    {
        m_device->cancelRead();
    }

    int Tunnel::mtu() const
    {
        return m_device->mtu();
    }

    std::vector<net::IpPrefix> Tunnel::addresses()
    {
        return m_addrs;
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
    }
}

int libxtun_tunnel_new(struct libxtun_tunnel *tun, const struct libxtun_tunnel_opts *opts)
{
    if (tun == nullptr || opts == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    // TODO(cd-amn): handle all opts up to the specified size
    // If a newer xtun .dll/.so is used in already compiled application - it
    // should not break anything, just handle all available opts
    if (opts->size < sizeof(*opts)) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    if (opts->killswitch_mode < LIBXTUN_KILLSWITCH_MODE_DISABLED || opts->killswitch_mode > LIBXTUN_KILLSWITCH_MODE_LAST) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto res = libxtun::Tunnel::fromOpts(*opts);
    if (!res) {
        return res.error();
    }

    tun->handle = res.value().release();
    return LIBXTUN_OK;
}

int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, int fd)
{
    if (tun == nullptr || fd < 0) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    auto res = libxtun::Tunnel::fromFd(fd);
    if (!res) {
        return res.error();
    }

    tun->handle = res.value().release();
    return LIBXTUN_OK;
}

int libxtun_tunnel_new_from_name(struct libxtun_tunnel *tun, const char *name)
{
    if (tun == nullptr || name == nullptr || name[0] == '\0') {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    auto res = libxtun::Tunnel::fromName(name);
    if (!res) {
        return res.error();
    }

    tun->handle = res.value().release();
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

int libxtun_tunnel_start(struct libxtun_tunnel *tun)
{
    if (tun == nullptr || tun->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }
    return reinterpret_cast<libxtun::Tunnel *>(tun->handle)->start();
}

int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    if (tun == nullptr || tun->handle == nullptr || proxy == nullptr || proxy->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    return obj->attachProxy(reinterpret_cast<libxtun::Proxy *>(proxy->handle));
}

void libxtun_tunnel_detach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    if (tun == nullptr || tun->handle == nullptr || proxy == nullptr || proxy->handle == nullptr) {
        return;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    obj->detachProxy(reinterpret_cast<libxtun::Proxy *>(proxy->handle));
}
