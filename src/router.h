#ifndef ROUTER_H
#define ROUTER_H

#include "net/ip.h"
#include "xtun.h"

#include <memory>
#include <string>
#include <vector>

namespace libxtun
{
    class RouterListener
    {
    public:
        virtual ~RouterListener() = default;

        virtual void onUplinkChanged() = 0;
    };

    class Router
    {
    public:
        explicit Router(RouterListener &listener) : m_listener(listener)
        {
        }
        virtual ~Router() = default;

        virtual libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                                 const std::vector<std::string> &addresses, int mtu) = 0;
        libxtun_error setProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                     const std::vector<net::IpPrefix> &excludes);
        void clearProxyRoutes();
        virtual void revert() = 0;
        virtual void protectSocket(int fd) = 0;
        virtual void onRouteChanged() {}

        static std::unique_ptr<Router> create(RouterListener &listener);

    protected:
        virtual libxtun_error addProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                             const std::vector<net::IpPrefix> &excludes) = 0;
        virtual void removeProxyRoutes() = 0;

        RouterListener &m_listener;

    private:
        std::vector<net::IpPrefix> m_appliedRoutes;
        std::vector<net::IpPrefix> m_appliedExcludes;
    };
}

#endif // ROUTER_H
