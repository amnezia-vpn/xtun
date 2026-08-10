#include "router.h"

#include <cstdint>
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
    uint32_t bypassToken() override;

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
};


}

#endif // ROUTER_WINDOWS_H
