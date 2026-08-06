#include "router.h"

#include <cstdint>
#include <mutex>

#ifndef ROUTER_LINUX_H
#define ROUTER_LINUX_H

namespace libxtun {


class LinuxRouter : public Router {
  public:
    int configureInterface(const std::string &ifname, int ifindex,
                           const std::vector<std::string> &addresses, int mtu) override;
    int setProxyRoutes(const std::vector<std::string> &routes) override;
    void clearProxyRoutes() override;
    void revert() override;
    uint32_t bypassToken() override;

  private:
    int setMtu(int mtu);
    int setUp();
    int updateAddress(const std::string &cidr, bool add);
    int updateRouteFor(const std::string &cidr, bool add);
    int updateFullTunnelRoutes(int family, bool add);
    int updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                   int suppressPrefixLen, uint32_t priority);
    int setDns(const std::vector<std::string> &servers);
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
