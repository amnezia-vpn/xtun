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
        std::vector<net::IpAddress> dnsServers;
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
                                                         ClientCallbacks callbacks);

        Proxy(ClientCallbacks callbacks);
        virtual ~Proxy();

        virtual const char *name() = 0;

        virtual void attachIo(TunnelIo *io);
        virtual void event(ProxyEvent ev) = 0;
        virtual ProxyProfile profile() const = 0;

    protected:
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
    };
}

#endif // PROXY_H
