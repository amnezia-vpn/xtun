#ifndef ROUTER_MACOS_H
#define ROUTER_MACOS_H

#include "router.h"
#include "xtun.h"

#include <mutex>

namespace libxtun
{
    class MacosRouter : public Router
    {
    public:
        explicit MacosRouter(RouterListener &listener) : Router(listener)
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
            unsigned ifindex = 0;
            unsigned char gw[16] = { 0 };

            friend bool operator==(const Uplink &, const Uplink &) = default;
        };

        libxtun_error setMtu(int mtu);
        libxtun_error setUp();
        libxtun_error addAddress(const std::string &cidr);
        libxtun_error rtSend(int family, const unsigned char *dst, int prefix, const void *gw, unsigned gwLen,
                             int flags, unsigned index, bool add);
        libxtun_error updateRoute(int family, const unsigned char *dst, int prefix, bool add);
        libxtun_error updateGatewayRoute(int family, const unsigned char *dst, int prefix, const unsigned char *gw,
                                         unsigned scope, bool add);
        libxtun_error updateRouteFor(const net::IpPrefix &prefix, bool add);
        libxtun_error updateFullTunnelRoutes(int family, bool add);
        libxtun_error updateUplinkRoutes(int family, const Uplink &uplink, bool add);
        Uplink getGatewayAndIface(int family);

        std::recursive_mutex m_mtx;
        int m_ifindex = -1;
        std::string m_ifname;
        std::vector<std::string> m_addresses;
        std::vector<net::IpPrefix> m_routes;
        std::vector<net::IpPrefix> m_excludes;
        bool m_fullV4 = false;
        bool m_fullV6 = false;
        Uplink m_uplinkV4;
        Uplink m_uplinkV6;
        int m_rtseq = 1;
    };
}

#endif // ROUTER_MACOS_H
