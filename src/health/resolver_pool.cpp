#include "resolver_pool.h"

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>

namespace libxtun::health
{
    namespace
    {

        constexpr std::array<std::string_view, 4> PUBLIC_RESOLVERS { "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111",
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

    ResolverPool::ResolverPool(std::span<const std::string> configuredServers,
                               std::span<const std::string> tunnelAddresses, std::span<const std::string> tunnelRoutes)
        : m_candidates(parseAddresses(configuredServers)),
          m_tunnelAddresses(parseAddresses(tunnelAddresses)),
          m_tunnelRoutes(net::PrefixSet::parseAll(tunnelRoutes))
    {
        m_configuredCount = m_candidates.size();
        for (std::string_view fallback : PUBLIC_RESOLVERS) {
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
                return m_tunnelRoutes.contains(addr) && localAddressFor(addr.family()).has_value();
            case Reachability::PhysicalInterface:
                return addr.globallyRoutable() && std::ranges::find(m_tunnelAddresses, addr) == m_tunnelAddresses.end();
            }
            return false;
        };

        const auto admissible = [&](std::size_t index) {
            if (index < m_configuredCount || via != Reachability::InsideTunnel) {
                return true;
            }
            return m_tunnelRoutes.hasDefaultRoute(m_candidates[index].family());
        };

        const auto indices = std::views::iota(std::size_t { 0 }, m_candidates.size());
        const auto hit = std::ranges::find_if(
                indices, [&](std::size_t index) { return admissible(index) && reachable(m_candidates[index]); });
        return hit == indices.end() ? std::nullopt : std::optional { m_candidates[*hit] };
    }

    std::optional<net::IpAddress> ResolverPool::localAddressFor(int family) const
    {
        const auto hit = std::ranges::find_if(m_tunnelAddresses,
                                              [family](const net::IpAddress &addr) { return addr.family() == family; });
        return hit == m_tunnelAddresses.end() ? std::nullopt : std::optional { *hit };
    }

}
