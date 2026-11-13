#ifndef PROXY_H
#define PROXY_H

#include <xtun.h>

#include "io/awaiting_io.h"
#include "net/ip.h"
#include "tunnel_io.h"
#include "util/noncopyable.h"
#include "util/result.h"

#include <vector>

namespace libxtun
{
    enum class ProxyEvent {
        Up,
        Down,
        MtuUpdate
    };

    struct ProxyProfile
    {
        std::vector<net::IpPrefix> routes;
        std::vector<net::IpPrefix> includeRoutes;
        std::vector<net::IpPrefix> excludeRoutes;
        std::vector<net::IpAddress> dnsServers;
        int mtu = 0;
    };

    struct ClientCallbacks
    {
        void (*onSocket)(int fd, void *priv) = nullptr;
        void *onSocketPriv = nullptr;
        void (*onLog)(const char *message, void *priv) = nullptr;
        void *onLogPriv = nullptr;
        void (*onStatus)(int status, void *priv) = nullptr;
        void *onStatusPriv = nullptr;
    };

    class Proxy : private NonCopyable
    {
    public:
        static ResultXtun<std::unique_ptr<Proxy>> create(libxtun_proxy_proto proto, const char *conf,
                                                         ClientCallbacks callbacks,
                                                         const libxtun_proxy_opts *opts = nullptr);

        Proxy(ClientCallbacks callbacks);
        virtual ~Proxy();

        virtual const char *name() = 0;

        virtual void attachIo(TunnelIo *io);
        virtual void event(ProxyEvent ev) = 0;
        ProxyProfile profile() const;

    protected:
        virtual ProxyProfile buildProfile() const = 0;

        static int cTunRead(void *b, int len, void *priv)
        {
            return reinterpret_cast<Proxy *>(priv)->tunRead(b, len);
        }
        int tunRead(void *b, int len);

        static int cTunWrite(void *b, int len, void *priv)
        {
            return reinterpret_cast<Proxy *>(priv)->tunWrite(b, len);
        }
        int tunWrite(void *b, int len);

        static int cTunMtu(void *priv)
        {
            return reinterpret_cast<Proxy *>(priv)->tunMtu();
        }
        int tunMtu();

        static void cSockCb(int fd, void *priv)
        {
            return reinterpret_cast<Proxy *>(priv)->sockCb(fd);
        }
        void sockCb(int fd);

        static void cEmitLog(char *str, void *priv)
        {
            return reinterpret_cast<Proxy *>(priv)->emitLog(str);
        }
        void emitLog(char *str);
    
    protected:
        void publishStatus(libxtun_status status);

        AwaitingIo m_io;
        ClientCallbacks m_callbacks;
        std::vector<net::IpPrefix> m_includeRoutes;
        std::vector<net::IpPrefix> m_excludeRoutes;
    };
}

#endif // PROXY_H
