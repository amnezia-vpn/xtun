#include "router.h"

#include <mutex>

#ifndef ROUTER_WINDOWS_H
#define ROUTER_WINDOWS_H

namespace libxtun {


class WindowsRouter : public Router {
  public:
    int configureInterface(const std::string &ifname, int ifindex,
                           const std::vector<std::string> &addresses, int mtu) override;
    int setProxyRoutes(const std::vector<std::string> &routes) override;
    void clearProxyRoutes() override;
    void revert() override;
    int bypassSocket(int fd, int family) override;
    bool bypassChanged() override;

  private:
    int addAddress(const std::string &cidr);
    int removeAddress(const std::string &cidr);
    int setMtuAndMetric(int family, int mtu);
    int updateRouteFor(const std::string &cidr, bool add);
    unsigned physicalDefaultIfindex();

    std::recursive_mutex m_mtx;
    unsigned long m_ifindex = 0;  // NET_IFINDEX
    std::vector<std::string> m_addresses;
    std::vector<std::string> m_routes;
    unsigned m_bypassIfindex = 0;
};


}

#endif // ROUTER_WINDOWS_H
