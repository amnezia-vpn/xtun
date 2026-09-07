#ifndef ROUTER_LINUX_H
#define ROUTER_LINUX_H

#include "router.h"

#include <cstdint>
#include <mutex>

namespace libxtun
{
    class LinuxRouter : public Router
    {
    public:
        libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                         const std::vector<std::string> &addresses, int mtu) override;
        libxtun_error setProxyRoutes(const std::vector<std::string> &routes) override;
        void clearProxyRoutes() override;
        void revert() override;
        void protectSocket(int fd) override;

    private:
        libxtun_error setMtu(int mtu);
        libxtun_error setUp();
        libxtun_error updateAddress(const std::string &cidr, bool add);
        libxtun_error updateRouteFor(const std::string &cidr, bool add);
        libxtun_error updateFullTunnelRoutes(int family, bool add);
        libxtun_error updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                                 int suppressPrefixLen, uint32_t priority);
        libxtun_error setDns(const std::vector<std::string> &servers);
        void revertDns();

        std::recursive_mutex m_mtx;
        int m_ifindex = -1;
        std::string m_ifname;
        std::vector<std::string> m_addresses;
        std::vector<std::string> m_routes;
        bool m_fullV4 = false;
        bool m_fullV6 = false;
        bool m_dnsApplied = false;
    };
}

#endif // ROUTER_LINUX_H
