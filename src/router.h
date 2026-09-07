#ifndef ROUTER_H
#define ROUTER_H

#include "xtun.h"

#include <memory>
#include <string>
#include <vector>

namespace libxtun
{
    class Router
    {
    public:
        virtual ~Router() = default;

        virtual libxtun_error configureInterface(const std::string &ifname, int ifindex,
                                                 const std::vector<std::string> &addresses, int mtu) = 0;

        virtual libxtun_error setProxyRoutes(const std::vector<std::string> &routes) = 0;
        virtual void clearProxyRoutes() = 0;
        virtual void revert() = 0;
        virtual void protectSocket(int fd) = 0;

        static std::unique_ptr<Router> create();
    };
}

#endif // ROUTER_H
