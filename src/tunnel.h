#ifndef LIBXTUN_TUNNEL_H
#define LIBXTUN_TUNNEL_H

#include "killswitch.h"
#include "net/ip.h"
#include "proxy.h"
#include "router.h"
#include "tun_device.h"
#include "tunnel_io.h"
#include "util/result.h"
#include "xtun.h"

#include <memory>
#include <mutex>
#include <string>

namespace libxtun
{
    class Tunnel : public TunnelIo, private TunDeviceListener, private ProxyProfileListener
    {
    public:
        enum class Event {
            Up,
            Down,
            MtuUpdate
        };

        static ResultXtun<std::unique_ptr<Tunnel>> fromOpts(const libxtun_tunnel_opts &opts);
        static ResultXtun<std::unique_ptr<Tunnel>> fromFd(int fd);
        static ResultXtun<std::unique_ptr<Tunnel>> fromName(const char *name);

        ~Tunnel();

        // Do not call attachProxy()/detachProxy() from Proxy callbacks: the caller may already hold
        // the mutex these methods need, causing a deadlock. Do not destroy the tunnel here either.
        int attachProxy(Proxy *proxy);
        libxtun_error detachProxy(Proxy *proxy);

        int start();

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;
        libxtun_error protectSocket(int fd) override;
        void wake() override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

        const std::string &name() const
        {
            return m_device->name();
        }

    private:
        Tunnel() = default;

        void emit(Event ev);

        void onLinkStateChanged(bool up) override;
        void onMtuChanged(int) override;
        void onRouteChanged() override;

        libxtun_error onProfileChanged(Proxy &source, const ProxyProfile &snapshot) override;
        libxtun_error applyProxyProfile(const ProxyProfile &profile);
        libxtun_error detachProxyLocked(Proxy *proxy);

        std::unique_ptr<TunDevice> m_device;
        std::unique_ptr<Router> m_router;
        std::unique_ptr<Killswitch> m_killswitch;

        // Keeps attach, detach and event delivery from using a proxy at the same time.
        std::mutex m_proxyLifecycleMutex;
        // Protects m_proxy, m_started and route application against concurrent notifications.
        std::mutex m_mutex;
        bool m_started = false;
        Proxy *m_proxy = nullptr;
    };
}

#endif // TUNNEL_H
