#ifndef ROUTER_WINDOWS_H
#define ROUTER_WINDOWS_H

#include "router.h"

#include <ifdef.h>
#include <netioapi.h>

#include <mutex>

namespace libxtun
{
    class WindowsRouter : public Router
    {
    public:
        explicit WindowsRouter(std::function<void()> onUplinkChanged) : Router(std::move(onUplinkChanged))
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
        struct Uplink
        {
            NET_IFINDEX ifindex = 0;
            net::IpAddress gw;

            friend bool operator==(const Uplink &, const Uplink &) = default;
        };

        libxtun_error addAddress(const std::string &cidr);
        libxtun_error removeAddress(const std::string &cidr);
        libxtun_error setMtuAndMetric(int family, int mtu);
        libxtun_error updateRouteFor(const net::IpPrefix &prefix, bool add);
        Uplink getUplink(int family);

        std::recursive_mutex m_mtx;
        unsigned long m_ifindex = 0; // NET_IFINDEX
        std::vector<std::string> m_addresses;
        std::vector<net::IpPrefix> m_routes;
        Uplink m_uplinkV4;
        Uplink m_uplinkV6;
    };
}

#endif // ROUTER_WINDOWS_H
