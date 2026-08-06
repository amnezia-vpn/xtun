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
    uint32_t bypassToken() override;

  private:
    // The physical uplink a full tunnel's scoped bypass routes point at, kept so
    // they can be removed exactly even if the uplink later changes.
    struct ScopedBypass {
        bool active = false;
        unsigned scope = 0;
        unsigned char gw[16] = {0};
    };

    int setMtu(int mtu);
    int setUp();
    int addAddress(const std::string &cidr);
    int rtSend(int family, const unsigned char *dst, int prefix, const void *gw,
                  unsigned gwLen, int flags, unsigned index, bool add);
    int updateRoute(int family, const unsigned char *dst, int prefix, bool add);
    int updateScopedRoute(int family, const unsigned char *dst, int prefix,
                          const unsigned char *gw, unsigned scope, bool add);
    int updateRouteFor(const std::string &cidr, bool add);
    int updateFullTunnelRoutes(int family, bool add);
    bool getGatewayAndIface(int family, int &ifindex, unsigned char *gw);

    std::recursive_mutex m_mtx;
    int m_ifindex = -1;
    std::string m_ifname;
    std::vector<std::string> m_addresses;
    std::vector<std::string> m_routes;
    bool m_fullV4 = false;
    bool m_fullV6 = false;
    ScopedBypass m_bypassV4;
    ScopedBypass m_bypassV6;
    int m_rtseq = 1;
};


}

#endif // ROUTER_MACOS_H
