#include "killswitch.h"
#include "xtun.h"
#include <algorithm>
#include <mutex>
#include <vector>

namespace libxtun
{
    namespace
    {
        std::vector<net::IpPrefix> protectedSet(const std::vector<net::IpPrefix> &routes)
        {
            if (routes.empty()) {
                return {};
            }

            const auto included = [&routes](int family) {
                return std::ranges::any_of(routes, [family](const net::IpPrefix &route) {
                    return route.address().family() == family;
                });
            };

            std::vector<net::IpPrefix> prefixes = routes;
            if (!included(AF_INET)) {
                prefixes.emplace_back(net::IpAddress::fromV4(in_addr {}), 0);
            }
            if (!included(AF_INET6)) {
                prefixes.emplace_back(net::IpAddress::fromV6(in6_addr {}), 0);
            }
            return prefixes;
        }
    }

    libxtun_error Killswitch::update(int ifIndex, const std::string &ifName)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        switch(m_mode) {
        case LIBXTUN_KILLSWITCH_MODE_DISABLED:
            // clear rules installed by HARD
            remove();
            m_installed = false;
            return LIBXTUN_OK;
        case LIBXTUN_KILLSWITCH_MODE_SOFT:
        case LIBXTUN_KILLSWITCH_MODE_HARD:
            if (m_installed) {
                return LIBXTUN_OK;
            }
            auto rc = install(ifIndex, ifName);
            m_installed = rc == LIBXTUN_OK;
            return rc;
        }

        return LIBXTUN_ERR_KILLSWITCH;
    }

    libxtun_error Killswitch::protect(const std::vector<net::IpPrefix> &routes,
                                      const std::vector<net::IpPrefix> &excludes,
                                      const std::vector<net::IpAddress> &resolvers)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_installed || (routes.empty() && persistent())) {
            return LIBXTUN_OK;
        }

        std::vector<net::IpAddress> dnsServers = resolvers;
        for (const net::IpAddress &exception : m_dnsExceptions) {
            if (std::ranges::find(dnsServers, exception) == dnsServers.end()) {
                dnsServers.push_back(exception);
            }
        }
        return setProtected(protectedSet(routes), excludes, dnsServers);
    }
}