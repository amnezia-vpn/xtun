#include "router.h"

#ifndef ROUTER_LINUX_H
#define ROUTER_LINUX_H

namespace libxtun {


class LinuxRouter : public Router {
  public:
    int apply(const std::string &ifname, int ifindex, const NetworkConfig &cfg) override;
    void revert() override;

  private:
    int setMtu(int mtu);
    int setUp();
    int changeAddress(const std::string &cidr, bool add);
    int changeRoute(const std::string &cidr, bool add);
    int setDns(const std::vector<std::string> &servers);
    void revertDns();

    int m_ifindex = -1;
    std::string m_ifname;
    std::vector<std::string> m_addresses;
    std::vector<std::string> m_routes;
    bool m_dnsApplied = false;
};


}

#endif // ROUTER_LINUX_H
