#ifndef TEST_SOCKET_H
#define TEST_SOCKET_H

#include "proxy.h"
#include "wrapper.h"
#include "xtun.h"

namespace libxtun::test
{
    class SockBindRemover : public ProxyWrapper
    {
    public:
        ClientCallbacks &wrapCallbacks(ClientCallbacks &callbacks) override
        {
            callbacks.onSocket = SockBindRemover::cSockBind;
            callbacks.onSocketPriv = this;
            return callbacks;
        }
        ClientCallbacks defaultCallbacks() override
        {
            ClientCallbacks callbacks {};
            return wrapCallbacks(callbacks);
        }

        libxtun_proxy &wrapProxy(libxtun_proxy &proxy) override
        {
            proxy.onsockspawn = SockBindRemover::cSockBind;
            proxy.onsockspawn_priv = this;
            return proxy;
        }
        libxtun_proxy defaultProxy() override
        {
            libxtun_proxy proxy {};
            return wrapProxy(proxy);
        }

        static void cSockBind(int fd, void *priv)
        {
            reinterpret_cast<SockBindRemover *>(priv)->sockBind(fd);
        }
        void sockBind(int fd)
        {
#if defined(WIN32)
            SOCKET s = fd;
            DWORD val = 0;
            ::setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<const char *>(&val), sizeof(val));
            val = ::htonl(val); // IP_UNICAST_IF expects index in network byte order
            ::setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char *>(&val), sizeof(val));
#elif defined(__APPLE__)
            unsigned idx = 0;
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
            ::setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
#elif defined(__linux__)
            unsigned mark = 0;
            ::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
#endif
        }
    };
}

#endif
