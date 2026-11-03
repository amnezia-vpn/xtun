#ifndef ROUTER_H
#define ROUTER_H

#include "net/ip.h"
#include "xtun.h"

#include <memory>
#include <mutex>
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
        virtual libxtun_error clearProxyRoutes() = 0;
        virtual void revert() = 0;
        virtual libxtun_error protectSocket(int fd) = 0;
        std::vector<net::IpPrefix> addresses();

        static std::unique_ptr<Router> create();

    protected:
        std::recursive_mutex m_mtx;
        // TODO: replace type to std::vector<net::IpPrefix> for both fields
        std::vector<std::string> m_addresses;
        std::vector<std::string> m_routes;
    };
}

#endif // ROUTER_H
