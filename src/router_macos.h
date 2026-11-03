#ifndef ROUTER_MACOS_H
#define ROUTER_MACOS_H

#include "router.h"
#include "xtun.h"

namespace libxtun
{
    class MacosRouter : public Router
    {
    public:
        libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                         const std::vector<std::string> &addresses, int mtu) override;
        libxtun_error setProxyRoutes(const std::vector<std::string> &routes) override;
        libxtun_error clearProxyRoutes() override;
        void revert() override;
        libxtun_error protectSocket(int fd) override;

    private:
        // The physical uplink a full tunnel's scoped bypass routes point at, kept so
        // they can be removed exactly even if the uplink later changes.
        struct ScopedBypass
        {
            bool active = false;
            unsigned scope = 0;
            unsigned char gw[16] = { 0 };
        };

        libxtun_error setMtu(int mtu);
        libxtun_error setUp();
        libxtun_error addAddress(const std::string &cidr);
        libxtun_error rtSend(int family, const unsigned char *dst, int prefix, const void *gw, unsigned gwLen,
                             int flags, unsigned index, bool add);
        libxtun_error updateRoute(int family, const unsigned char *dst, int prefix, bool add);
        libxtun_error updateScopedRoute(int family, const unsigned char *dst, int prefix, const unsigned char *gw,
                                        unsigned scope, bool add);
        libxtun_error updateRouteFor(const std::string &cidr, bool add);
        libxtun_error updateFullTunnelRoutes(int family, bool add);
        bool getGatewayAndIface(int family, int &ifindex, unsigned char *gw);
        unsigned physicalIfindex(int family);

        int m_ifindex = -1;
        std::string m_ifname;
        bool m_fullV4 = false;
        bool m_fullV6 = false;
        ScopedBypass m_bypassV4;
        ScopedBypass m_bypassV6;
        int m_rtseq = 1;
    };
}

#endif // ROUTER_MACOS_H
