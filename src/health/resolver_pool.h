#ifndef HEALTH_RESOLVER_POOL_H
#define HEALTH_RESOLVER_POOL_H

#include "net/ip.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace libxtun::health {

enum class Reachability { InsideTunnel, PhysicalInterface };

class ResolverPool {
  public:
    ResolverPool(std::span<const std::string> configured_servers,
                 std::span<const std::string> tunnel_addresses,
                 std::span<const std::string> tunnel_routes);

    [[nodiscard]] std::optional<net::IpAddress> select(Reachability via) const;
    [[nodiscard]] std::optional<net::IpAddress> localAddressFor(int family) const;

  private:
    std::vector<net::IpAddress> m_candidates;
    std::size_t m_configured_count = 0;
    std::vector<net::IpAddress> m_tunnel_addresses;
    net::PrefixSet m_tunnel_routes;
};

}

#endif // HEALTH_RESOLVER_POOL_H
