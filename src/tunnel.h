#ifndef LIBXTUN_TUNNEL_H
#define LIBXTUN_TUNNEL_H

#include "health/monitor.h"
#include "proxy.h"
#include "router.h"
#include "tun_device.h"
#include "xtun.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace libxtun
{

    class Tunnel : private TunDeviceListener
    {
    public:
        enum class Event {
            Up,
            Down,
            MtuUpdate
        };

        explicit Tunnel(const libxtun_tunnel_opts &opts);
        Tunnel(const libxtun_tunnel_opts &opts, std::unique_ptr<TunDevice> device);
        ~Tunnel();

        int openTun();
        int adoptTun(int fd);
        int adoptTunByName(const char *name);

        const std::string &name() const
        {
            return m_device->name();
        }

        bool up() const;
        void onEvent(std::function<void(Event)> cb)
        {
            m_onEvent = std::move(cb);
        }

        int attachProxy(Proxy *proxy);
        int start();

    private:
        friend class Proxy;

        class BypassSocketRegistry
        {
        public:
            void add(Router &router, int fd, int family);
            void rebind(Router &router);
            void clear();

        private:
            mutable std::mutex m_mtx;
            std::unordered_map<int, int> m_sockets;
        };

        int completeDeviceSetup();

        void registerBypassSocket(int fd, int family);
        void bypassSocket(int fd, int family);
        void detachProxy(Proxy *proxy) noexcept;

        void shutdownProxy(Proxy *expected) noexcept;
        [[nodiscard]] Proxy *takeProxy(Proxy *expected = nullptr) noexcept;
        health::HealthConfig healthConfigFor(const ProxyProfile &profile);
        void cancelRead()
        {
            m_device->cancelRead();
        }
        void wakeRead()
        {
            m_device->wakeRead();
        }

        void emit(Event ev);

        void onRouteChange();

        void onLinkStateChanged(bool up) override;
        void onMtuChanged(int) override;
        void onRouteChanged() override;

        std::vector<std::string> m_dns;
        std::vector<std::string> m_dnsExceptions;
        libxtun_killswitch_mode m_killswitchMode;
        std::vector<std::string> m_ifAddrs;
        int m_confMtu;
        std::unique_ptr<Router> m_router;
        std::unique_ptr<TunDevice> m_device;
        bool m_started = false;

        BypassSocketRegistry m_bypass_sockets;
        health::HealthSettings m_health_settings;

        std::function<void(Event)> m_onEvent;
        std::mutex m_proxyMtx;
        Proxy *m_proxy = nullptr;
    };

}

#endif // TUNNEL_H
