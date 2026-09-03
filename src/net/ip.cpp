#include "ip.h"

#include <algorithm>
#include <charconv>
#include <cstring>

namespace libxtun::net
{
    namespace
    {

        constexpr std::size_t V4_OCTETS = 4;
        constexpr std::size_t V6_OCTETS = 16;

        std::size_t octetsFor(int family) noexcept
        {
            return family == AF_INET6 ? V6_OCTETS : V4_OCTETS;
        }

        unsigned octetAt(std::span<const std::byte> octets, std::size_t index) noexcept
        {
            return std::to_integer<unsigned>(octets[index]);
        }

        bool routableV4(std::span<const std::byte> o) noexcept
        {
            const unsigned first = octetAt(o, 0);
            const unsigned second = octetAt(o, 1);

            if (first == 0 || first == 127 || first >= 224) {
                return false;
            }
            if (first == 10 || (first == 172 && (second & 0xf0u) == 16) || (first == 192 && second == 168)) {
                return false;
            }
            if (first == 169 && second == 254) {
                return false;
            }
            return !(first == 100 && (second & 0xc0u) == 64);
        }

        bool routableV6(std::span<const std::byte> o) noexcept
        {
            in6_addr addr {};
            std::memcpy(&addr, o.data(), V6_OCTETS);

            if (IN6_IS_ADDR_UNSPECIFIED(&addr) || IN6_IS_ADDR_LOOPBACK(&addr) || IN6_IS_ADDR_LINKLOCAL(&addr)
                || IN6_IS_ADDR_SITELOCAL(&addr) || IN6_IS_ADDR_MULTICAST(&addr) || IN6_IS_ADDR_V4MAPPED(&addr)) {
                return false;
            }
            return (octetAt(o, 0) & 0xfeu) != 0xfcu;
        }
    }

    std::optional<IpAddress> IpAddress::parse(std::string_view text)
    {
        const std::string value(text);

        in_addr v4 {};
        if (::inet_pton(AF_INET, value.c_str(), &v4) == 1) {
            return fromV4(v4);
        }
        in6_addr v6 {};
        if (::inet_pton(AF_INET6, value.c_str(), &v6) == 1) {
            return fromV6(v6);
        }
        return std::nullopt;
    }

    IpAddress IpAddress::fromV4(const in_addr &addr) noexcept
    {
        IpAddress out;
        out.m_family = AF_INET;
        std::memcpy(out.m_octets.data(), &addr, V4_OCTETS);
        return out;
    }

    IpAddress IpAddress::fromV6(const in6_addr &addr) noexcept
    {
        IpAddress out;
        out.m_family = AF_INET6;
        std::memcpy(out.m_octets.data(), &addr, V6_OCTETS);
        return out;
    }

    std::span<const std::byte> IpAddress::octets() const noexcept
    {
        return { m_octets.data(), valid() ? octetsFor(m_family) : 0 };
    }

    std::string IpAddress::toString() const
    {
        if (!valid()) {
            return {};
        }
        std::array<char, INET6_ADDRSTRLEN> buf {};
        if (::inet_ntop(m_family, m_octets.data(), buf.data(), buf.size()) == nullptr) {
            return {};
        }
        return buf.data();
    }

    bool IpAddress::globallyRoutable() const noexcept
    {
        switch (m_family) {
        case AF_INET: return routableV4(octets());
        case AF_INET6: return routableV6(octets());
        default: return false;
        }
    }

    IpPrefix::IpPrefix(IpAddress address, unsigned bits) noexcept : m_address(address), m_bits(bits)
    {
    }

    std::optional<IpPrefix> IpPrefix::parse(std::string_view cidr)
    {
        const auto slash = cidr.find('/');
        const auto address = IpAddress::parse(cidr.substr(0, slash));
        if (!address) {
            return std::nullopt;
        }

        const unsigned hostBits = address->family() == AF_INET6 ? 128u : 32u;
        if (slash == std::string_view::npos) {
            return IpPrefix(*address, hostBits);
        }

        const std::string_view text = cidr.substr(slash + 1);
        unsigned bits = 0;
        const auto *end = text.data() + text.size();
        const auto [stopped, ec] = std::from_chars(text.data(), end, bits);
        if (ec != std::errc {} || stopped != end || bits > hostBits) {
            return std::nullopt;
        }
        return IpPrefix(*address, bits);
    }

    bool IpPrefix::contains(const IpAddress &addr) const noexcept
    {
        if (!m_address.valid() || addr.family() != m_address.family()) {
            return false;
        }

        const auto expected = m_address.octets();
        const auto actual = addr.octets();
        const std::size_t whole = m_bits / 8;
        const unsigned remainder = m_bits % 8;

        if (whole > 0 && std::memcmp(expected.data(), actual.data(), whole) != 0) {
            return false;
        }
        if (remainder == 0) {
            return true;
        }

        const unsigned mask = (0xffu << (8 - remainder)) & 0xffu;
        return (octetAt(expected, whole) & mask) == (octetAt(actual, whole) & mask);
    }

    PrefixSet PrefixSet::parseAll(std::span<const std::string> cidrs)
    {
        PrefixSet out;
        for (const std::string &cidr : cidrs) {
            if (const auto prefix = IpPrefix::parse(cidr)) {
                out.insert(*prefix);
            }
        }
        return out;
    }

    void PrefixSet::insert(IpPrefix prefix)
    {
        m_prefixes.push_back(prefix);
    }

    bool PrefixSet::contains(const IpAddress &addr) const noexcept
    {
        return std::ranges::any_of(m_prefixes, [&addr](const IpPrefix &prefix) { return prefix.contains(addr); });
    }

    bool PrefixSet::hasDefaultRoute(int family) const noexcept
    {
        return std::ranges::any_of(m_prefixes, [family](const IpPrefix &prefix) {
            return prefix.isDefaultRoute() && prefix.address().family() == family;
        });
    }

    SockAddr::SockAddr(const IpAddress &addr, std::uint16_t port) noexcept
    {
        const auto octets = addr.octets();

        if (addr.family() == AF_INET) {
            auto *v4 = reinterpret_cast<sockaddr_in *>(&m_storage);
            v4->sin_family = AF_INET;
            v4->sin_port = htons(port);
            std::memcpy(&v4->sin_addr, octets.data(), octets.size());
            m_size = sizeof(sockaddr_in);
        } else if (addr.family() == AF_INET6) {
            auto *v6 = reinterpret_cast<sockaddr_in6 *>(&m_storage);
            v6->sin6_family = AF_INET6;
            v6->sin6_port = htons(port);
            std::memcpy(&v6->sin6_addr, octets.data(), octets.size());
            m_size = sizeof(sockaddr_in6);
        }
    }

    const sockaddr *SockAddr::data() const noexcept
    {
        return reinterpret_cast<const sockaddr *>(&m_storage);
    }
}
