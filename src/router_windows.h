#ifndef ROUTER_WINDOWS_H
#define ROUTER_WINDOWS_H

#include "router.h"

namespace libxtun
{
    class WindowsRouter : public Router
    {
    public:
        libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                         const std::vector<std::string> &addresses, int mtu) override;
        libxtun_error setProxyRoutes(const std::vector<std::string> &routes) override;
        libxtun_error clearProxyRoutes() override;
        void revert() override;
        libxtun_error protectSocket(int fd) override;

    private:
        libxtun_error addAddress(const std::string &cidr);
        libxtun_error removeAddress(const std::string &cidr);
        libxtun_error setMtuAndMetric(int family, int mtu);
        libxtun_error updateRouteFor(const std::string &cidr, bool add);
        unsigned physicalDefaultIfindex(int family);

        unsigned long m_ifindex = 0; // NET_IFINDEX
    };
}

#endif // ROUTER_WINDOWS_H
