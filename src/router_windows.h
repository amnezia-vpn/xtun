#ifndef ROUTER_WINDOWS_H
#define ROUTER_WINDOWS_H

#include "net/uplink_windows.h"
#include "router.h"

#include <mutex>

namespace libxtun
{
    class WindowsRouter : public Router
    {
    public:
        explicit WindowsRouter(RouterListener &listener) : Router(listener)
        {
        }

        libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                         const std::vector<net::IpPrefix> &addresses, int mtu) override;
        void revert() override;
        void protectSocket(int fd) override;
        void onRouteChanged() override;

    protected:
        libxtun_error addProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                     const std::vector<net::IpPrefix> &excludes) override;
        void removeProxyRoutes() override;

    private:
        libxtun_error addAddress(const net::IpPrefix &prefix);
        libxtun_error removeAddress(const net::IpPrefix &prefix);
        libxtun_error setMtuAndMetric(int family, int mtu);
        libxtun_error updateRouteFor(const net::IpPrefix &prefix, bool add, const net::WindowsUplink *uplink = nullptr);
        libxtun_error updateUplinkRoutes(int family, const net::WindowsUplink &uplink, bool add);

        std::recursive_mutex m_mtx;
        unsigned long m_ifindex = 0; // NET_IFINDEX
        std::vector<net::IpPrefix> m_addresses;
        std::vector<net::IpPrefix> m_routes;
        std::vector<net::IpPrefix> m_excludes;
        net::WindowsUplink m_uplinkV4;
        net::WindowsUplink m_uplinkV6;
    };
}

#endif // ROUTER_WINDOWS_H
