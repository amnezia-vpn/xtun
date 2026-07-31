#include <memory>
#include <string>
#include <vector>

#ifndef ROUTER_H
#define ROUTER_H

namespace libxtun {


struct NetworkConfig {
    std::vector<std::string> addresses;
    std::vector<std::string> routes;
    std::vector<std::string> bypass;
    std::vector<std::string> dns;
    int mtu = 0;
};

class Router {
  public:
    virtual ~Router() = default;

    virtual int apply(const std::string &ifname, int ifindex, const NetworkConfig &cfg) = 0;
    virtual void revert() = 0;

    virtual void refresh() {}

    static std::unique_ptr<Router> create();
};


}

#endif // ROUTER_H
