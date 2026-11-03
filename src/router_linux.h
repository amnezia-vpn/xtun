#ifndef ROUTER_LINUX_H
#define ROUTER_LINUX_H

#include "router.h"

#include <cstdint>

namespace libxtun
{
    class LinuxRouter : public Router
    {
    public:
        libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                         const std::vector<std::string> &addresses, int mtu) override;
        libxtun_error setProxyRoutes(const std::vector<std::string> &routes) override;
        libxtun_error clearProxyRoutes() override;
        void revert() override;
        libxtun_error protectSocket(int fd) override;

    private:
        libxtun_error setMtu(int mtu);
        libxtun_error updateIpAddress(const net::IpPrefix &address, bool add);
        libxtun_error updateIpRoute(const net::IpPrefix &route, bool add);
        libxtun_error clearIpRoutes(int family);

        libxtun_error setUp();
        libxtun_error updateFullTunnelRoutes(int family, bool add);
        libxtun_error updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                                 int suppressPrefixLen, uint32_t priority);
        libxtun_error setDns(const std::vector<std::string> &servers);
        void revertDns();

        int m_ifindex = -1;
        std::string m_ifname;
        struct FullRoutes
        {
            bool route = false;                        // Created the default route in PROXY_TABLE.
            bool trafficToTunnelRule = false;          // Created the rule: mark != PROXY_FWMARK uses PROXY_TABLE.
            bool mainRoutesWithoutDefaultRule = false; // Created the rule for main-table routes other than default.
        };
        FullRoutes m_fullV4;
        FullRoutes m_fullV6;
        bool m_dnsApplied = false;
    };
}

#endif // ROUTER_LINUX_H
