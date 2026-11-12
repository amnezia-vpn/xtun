#ifndef ROUTER_H
#define ROUTER_H

#include "net/ip.h"
#include "xtun.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    class Router
    {
    public:
        explicit Router(std::function<void()> onUplinkChanged) : m_onUplinkChanged(std::move(onUplinkChanged))
        {
        }
        virtual ~Router() = default;

        virtual libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                                 const std::vector<std::string> &addresses, int mtu) = 0;

        virtual libxtun_error setProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                             const std::vector<net::IpPrefix> &excludes) = 0;
        virtual void clearProxyRoutes() = 0;
        virtual void revert() = 0;
        virtual void protectSocket(int fd) = 0;
        virtual void onRouteChanged() {}

        static std::unique_ptr<Router> create(std::function<void()> onUplinkChanged);

    protected:
        std::function<void()> m_onUplinkChanged;
    };
}

#endif // ROUTER_H
