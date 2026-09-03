#include "resolver_pool.h"

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>

namespace libxtun::health
{
    namespace
    {

        constexpr std::array<std::string_view, 4> kPublicResolvers { "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111",
                                                                     "2001:4860:4860::8888" };

        std::vector<net::IpAddress> parseAddresses(std::span<const std::string> texts)
        {
            std::vector<net::IpAddress> out;
            out.reserve(texts.size());
            for (const std::string &text : texts) {
                if (const auto prefix = net::IpPrefix::parse(text)) {
                    out.push_back(prefix->address());
                }
            }
            return out;
        }

    }

    ResolverPool::ResolverPool(std::span<const std::string> configured_servers,
                               std::span<const std::string> tunnel_addresses, std::span<const std::string> tunnel_routes)
        : m_candidates(parseAddresses(configured_servers)),
          m_tunnel_addresses(parseAddresses(tunnel_addresses)),
          m_tunnel_routes(net::PrefixSet::parseAll(tunnel_routes))
    {
        m_configured_count = m_candidates.size();
        for (std::string_view fallback : kPublicResolvers) {
            if (const auto address = net::IpAddress::parse(fallback)) {
                m_candidates.push_back(*address);
            }
        }
    }

    std::optional<net::IpAddress> ResolverPool::select(Reachability via) const
    {
        const auto reachable = [&](const net::IpAddress &addr) {
            switch (via) {
            case Reachability::InsideTunnel:
                return m_tunnel_routes.contains(addr) && localAddressFor(addr.family()).has_value();
            case Reachability::PhysicalInterface:
                return addr.globallyRoutable() && std::ranges::find(m_tunnel_addresses, addr) == m_tunnel_addresses.end();
            }
            return false;
        };

        const auto admissible = [&](std::size_t index) {
            if (index < m_configured_count || via != Reachability::InsideTunnel) {
                return true;
            }
            return m_tunnel_routes.hasDefaultRoute(m_candidates[index].family());
        };

        const auto indices = std::views::iota(std::size_t { 0 }, m_candidates.size());
        const auto hit = std::ranges::find_if(
                indices, [&](std::size_t index) { return admissible(index) && reachable(m_candidates[index]); });
        return hit == indices.end() ? std::nullopt : std::optional { m_candidates[*hit] };
    }

    std::optional<net::IpAddress> ResolverPool::localAddressFor(int family) const
    {
        const auto hit = std::ranges::find_if(m_tunnel_addresses,
                                              [family](const net::IpAddress &addr) { return addr.family() == family; });
        return hit == m_tunnel_addresses.end() ? std::nullopt : std::optional { *hit };
    }

}
