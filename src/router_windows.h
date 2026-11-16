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
                                         const std::vector<std::string> &addresses, int mtu) override;
        libxtun_error setProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                     const std::vector<net::IpPrefix> &excludes) override;
        void clearProxyRoutes() override;
        void revert() override;
        void protectSocket(int fd) override;
        void onRouteChanged() override;

    private:
        libxtun_error addAddress(const std::string &cidr);
        libxtun_error removeAddress(const std::string &cidr);
        libxtun_error setMtuAndMetric(int family, int mtu);
        libxtun_error updateRouteFor(const net::IpPrefix &prefix, bool add, const net::WindowsUplink *uplink = nullptr);
        libxtun_error updateUplinkRoutes(int family, const net::WindowsUplink &uplink, bool add);

        std::recursive_mutex m_mtx;
        unsigned long m_ifindex = 0; // NET_IFINDEX
        std::vector<std::string> m_addresses;
        std::vector<net::IpPrefix> m_routes;
        std::vector<net::IpPrefix> m_excludes;
        net::WindowsUplink m_uplinkV4;
        net::WindowsUplink m_uplinkV6;
    };
}

#endif // ROUTER_WINDOWS_H
