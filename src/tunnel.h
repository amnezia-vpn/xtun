#ifndef LIBXTUN_TUNNEL_H
#define LIBXTUN_TUNNEL_H

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
    class Tunnel : public TunnelIo, private TunDeviceListener
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

        int attachProxy(Proxy *proxy);
        int start();

        int read(std::span<std::byte> buf) noexcept override;
        int write(std::span<const std::byte> packet) noexcept override;
        int mtu() const noexcept override;
        void protectSocket(int fd) noexcept override;

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

        std::unique_ptr<TunDevice> m_device;
        std::unique_ptr<Router> m_router;

        std::mutex m_mutex;
        bool m_started = false;
        Proxy *m_proxy = nullptr;
    };
}

#endif // TUNNEL_H
