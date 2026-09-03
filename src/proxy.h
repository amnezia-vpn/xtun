#ifndef PROXY_H
#define PROXY_H

#include <xtun.h>

#include "health/probe.h"
#include "health/state.h"
#include "tunnel_io.h"

#include <atomic>
#include <memory>
#include <string>
#include <vector>

namespace libxtun
{

    class Tunnel;

    namespace health
    {
        struct HealthConfig;
    }

    enum class ProxyEvent {
        Up,
        Down,
        MtuUpdate
    };

    struct ProxyProfile
    {
        std::vector<std::string> routes;
        std::vector<std::string> dns_servers;
        std::vector<std::string> addresses;
        health::ProbeStyle probe_style = health::ProbeStyle::Datagram;
    };

    struct ClientCallbacks
    {
        void (*on_socket)(int fd, void *priv) = nullptr;
        void *on_socket_priv = nullptr;
        void (*on_log)(const char *message, void *priv) = nullptr;
        void *on_log_priv = nullptr;
        void (*on_status)(int status, void *priv) = nullptr;
        void *on_status_priv = nullptr;
    };

    class Proxy : private health::HealthListener
    {
    public:
        Proxy();
        ~Proxy() override = 0;

        virtual const char *name() = 0;

        virtual int start(TunnelIo &io) = 0;
        virtual void event(ProxyEvent ev) = 0;
        virtual void stop() = 0;

        virtual ProxyProfile profile() const = 0;

        void bind(const ClientCallbacks &callbacks)
        {
            m_callbacks = callbacks;
        }
        void setInterface(const std::string &ifname)
        {
            m_ifname = ifname;
        }

    protected:
        void cancelIo();
        void emitLog(const char *message) noexcept;
        void emitStatus(int status) noexcept;
        void registerBypassSocket(int fd, int family);
        void bypassSocket(int fd, int family);

        std::string m_ifname;

    private:
        friend class Tunnel;

        void onConnectionState(health::ConnectionState state) noexcept override;

        [[nodiscard]] TunnelIo &attach(Tunnel &tunnel, health::HealthConfig config, TunnelIo &device);
        void detach() noexcept;

        health::HealthSubsystem *health() noexcept
        {
            return m_health.get();
        }

        ClientCallbacks m_callbacks;
        std::atomic<Tunnel *> m_tunnel { nullptr };
        std::unique_ptr<health::HealthSubsystem> m_health;
    };

}

#endif // PROXY_H
