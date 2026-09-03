#ifndef HEALTH_RESOLVER_POOL_H
#define HEALTH_RESOLVER_POOL_H

#include "net/ip.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace libxtun::health
{

    enum class Reachability {
        InsideTunnel,
        PhysicalInterface
    };

    class ResolverPool
    {
    public:
        ResolverPool(std::span<const std::string> configuredServers, std::span<const std::string> tunnelAddresses,
                     std::span<const std::string> tunnelRoutes);

        [[nodiscard]] std::optional<net::IpAddress> select(Reachability via) const;
        [[nodiscard]] std::optional<net::IpAddress> localAddressFor(int family) const;

    private:
        std::vector<net::IpAddress> m_candidates;
        std::size_t m_configuredCount = 0;
        std::vector<net::IpAddress> m_tunnelAddresses;
        net::PrefixSet m_tunnelRoutes;
    };

}

#endif // HEALTH_RESOLVER_POOL_H
