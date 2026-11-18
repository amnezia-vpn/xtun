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
        explicit LinuxRouter(RouterListener &listener) : Router(listener)
        {
        }

        libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                         const std::vector<std::string> &addresses, int mtu) override;
        void revert() override;
        void protectSocket(int fd) override;

    protected:
        libxtun_error addProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                     const std::vector<net::IpPrefix> &excludes) override;
        void removeProxyRoutes() override;

    private:
        libxtun_error setMtu(int mtu);
        libxtun_error setUp();
        libxtun_error updateAddress(const std::string &cidr, bool add);
        libxtun_error updateRouteFor(const net::IpPrefix &prefix, bool add);
        libxtun_error updateTunnelRules(int family, bool add);
        libxtun_error updateExcludeRule(const net::IpPrefix &prefix, bool add);
        libxtun_error updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                                 int suppressPrefixLen, uint32_t priority, const net::IpPrefix *dst = nullptr);

        std::recursive_mutex m_mtx;
        int m_ifindex = -1;
        std::string m_ifname;
        std::vector<std::string> m_addresses;
        std::vector<net::IpPrefix> m_routes;
        std::vector<net::IpPrefix> m_excludes;
        bool m_rulesV4 = false;
        bool m_rulesV6 = false;
    };
}

#endif // ROUTER_LINUX_H
