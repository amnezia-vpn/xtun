#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#ifndef ROUTER_H
#define ROUTER_H

namespace libxtun {


class Router {
  public:
    virtual ~Router() = default;

    virtual int configureInterface(const std::string &ifname, int ifindex,
                                   const std::vector<std::string> &addresses, int mtu) = 0;

    virtual int setProxyRoutes(const std::vector<std::string> &routes) = 0;
    virtual void clearProxyRoutes() = 0;

    virtual void revert() = 0;

    // The value a proxy applies to its own socket so its traffic bypasses the
    // tun: an fwmark on Linux, the physical interface index (IP_BOUND_IF) on
    // macOS. The tunnel hands it to the proxy at attach.
    virtual uint32_t bypassToken() = 0;

    static std::unique_ptr<Router> create();
};


}

#endif // ROUTER_H
