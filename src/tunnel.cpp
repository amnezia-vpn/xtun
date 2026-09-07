#include "tunnel.h"
#include "proxy.h"
#include "tun_device.h"
#include "xtun.h"

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
    Tunnel::~Tunnel()
    {
        m_device->stopMonitor();
        m_device->cancelRead();
        if (m_router != nullptr) {
            m_router->revert();
        }
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromOpts(const libxtun_tunnel_opts &opts)
    {
        auto dev = createTunDevice();
        auto router = Router::create();

        if (auto rc = dev->open(); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        const auto ifAddrs = parseStrList(opts.if_addrs);
        if (auto rc = router->configureInterface(dev->name(), dev->ifIndex(), ifAddrs, opts.mtu); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_device = std::move(dev);
        tun->m_router = std::move(router);
        tun->m_device->startMonitor(*tun);
        return tun;
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromFd(int fd)
    {
        auto dev = createTunDevice();
        if (auto rc = dev->adoptFd(fd); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_device = std::move(dev);
        return tun;
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromName(const char *name)
    {
        auto dev = createTunDevice();
        if (auto rc = dev->adoptName(name); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_device = std::move(dev);
        return tun;
    }

    int Tunnel::attachProxy(Proxy *proxy)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (proxy == nullptr) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        if (m_proxy) {
            m_proxy->attachIo(nullptr);
            m_proxy = nullptr;
        }

        ProxyProfile profile = proxy->profile();

        if (m_router != nullptr) {
            m_router->clearProxyRoutes();
            if (auto rc = m_router->setProxyRoutes(profile.routes); rc != LIBXTUN_OK) {
                // FIXME: we are reverting too much in here. Should be rollback() or similar
                m_router->revert();
                return LIBXTUN_ERR_SYSTEM;
            }
        }

        // TODO(cd-amn): write DNS (if Tunnel is created via fromOpts)
        void(profile.dnsServers);

        m_device->resetReadCancellation();

        proxy->attachIo(this);
        m_proxy = proxy;

        return LIBXTUN_OK;
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

    int Tunnel::read(std::span<std::byte> buf) noexcept
    {
        return m_device->read(buf);
    }

    int Tunnel::write(std::span<const std::byte> packet) noexcept
    {
        return m_device->write(packet);
    }

    int Tunnel::mtu() const noexcept
    {
        return m_device->mtu();
    }

    void Tunnel::protectSocket(int fd) noexcept
    {
        if (m_router != nullptr) {
            m_router->protectSocket(fd);
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
