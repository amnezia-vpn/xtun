#include "router.h"

#include <mutex>

#ifndef ROUTER_LINUX_H
#define ROUTER_LINUX_H

namespace libxtun {


class LinuxRouter : public Router {
  public:
    int configureInterface(const std::string &ifname, int ifindex,
                           const std::vector<std::string> &addresses, int mtu) override;
    int setProxyRoutes(const std::vector<std::string> &routes,
                       const std::vector<std::string> &bypass) override;
    void clearProxyRoutes() override;
    void revert() override;
    void refresh() override;

  private:
    int setMtu(int mtu);
    int setUp();
    int changeAddress(const std::string &cidr, bool add);
    int changeTunnelRoute(const std::string &cidr, bool add);
    int changeBypassRoute(const std::string &ip, bool add);
    int setDns(const std::vector<std::string> &servers);
    void revertDns();

    std::recursive_mutex m_mtx;
    int m_ifindex = -1;
    std::string m_ifname;
    std::vector<std::string> m_addresses;
    std::vector<std::string> m_routes;
    std::vector<std::string> m_bypass;
    unsigned char m_gw4[16] = {0};
    unsigned char m_gw6[16] = {0};
    bool m_gw4Valid = false;
    bool m_gw6Valid = false;
    bool m_dnsApplied = false;
};


}

#endif // ROUTER_LINUX_H
