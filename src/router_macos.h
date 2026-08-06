#include "router.h"

#include <cstdint>
#include <mutex>

#ifndef ROUTER_MACOS_H
#define ROUTER_MACOS_H

namespace libxtun {


class MacosRouter : public Router {
  public:
    int configureInterface(const std::string &ifname, int ifindex,
                           const std::vector<std::string> &addresses, int mtu) override;
    int setProxyRoutes(const std::vector<std::string> &routes) override;
    void clearProxyRoutes() override;
    void revert() override;

  private:
    int setMtu(int mtu);
    int setUp();
    int addAddress(const std::string &cidr);
    int changeRoute(int family, const unsigned char *dst, int prefix, bool add);
    int changeTunnelRoute(const std::string &cidr, bool add);
    int setFullTunnel(int family, bool add);

    std::recursive_mutex m_mtx;
    int m_ifindex = -1;
    std::string m_ifname;
    std::vector<std::string> m_addresses;
    std::vector<std::string> m_routes;
    bool m_fullV4 = false;
    bool m_fullV6 = false;
    int m_rtseq = 1;
};


}

#endif // ROUTER_MACOS_H
