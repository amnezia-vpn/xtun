#ifndef LIBXTUN_TUNNEL_H
#define LIBXTUN_TUNNEL_H

#include "dispatch/dispatcher.h"
#include "dns.h"
#include "killswitch.h"
#include "net/ip.h"
#include "proxy.h"
#include "router.h"
#include "tun_device.h"
#include "tunnel_io.h"
#include "util/result.h"
#include "xtun.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace libxtun
{
    class Tunnel : public TunnelIo, public TunDeviceListener
    {
    public:
        using TunfactoryFunc = std::function<int(const std::vector<net::IpAddress> &, const std::vector<net::IpPrefix> &, int)>;

        enum class Event {
            Up,
            Down,
            MtuUpdate
        };

        static ResultXtun<std::unique_ptr<Tunnel>> fromOpts(const libxtun_tunnel_opts &opts);
        static ResultXtun<std::unique_ptr<Tunnel>> fromTunfactory(TunfactoryFunc tunfactory,
                                                                  std::vector<std::string> ifaddrs);

        ~Tunnel();

        int attachProxy(Proxy *proxy);
        void detachProxy(Proxy *proxy);

        int start();

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;
        void protectSocket(int fd) override;
        void wake() override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

        const std::string &name() const
        {
            return m_device->name();
        }

        void onLinkStateChanged(bool up) override;
        void onMtuChanged(int) override;
        void onRouteChanged() override;

    private:
        Tunnel();

        void emit(Event ev);
        int applyLocked(const ProxyProfile &profile);
        void teardownLocked();

        std::unique_ptr<TunDevice> m_device;
        std::unique_ptr<Router> m_router;
        std::unique_ptr<Dns> m_dns;
        std::unique_ptr<Killswitch> m_killswitch;

        std::mutex m_mutex;
        bool m_started = false;
        TunfactoryFunc m_tunfactory;
        std::vector<net::IpPrefix> m_addrs;
        std::vector<net::IpAddress> m_dnsDefaults;
        dispatch::Dispatcher m_dispatcher;
    };
}

#endif // TUNNEL_H
