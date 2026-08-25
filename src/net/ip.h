#ifndef NET_IP_H
#define NET_IP_H

#include "net/sys.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace libxtun::net {

class IpAddress {
  public:
    IpAddress() = default;

    [[nodiscard]] static std::optional<IpAddress> parse(std::string_view text);
    static IpAddress fromV4(const in_addr &addr) noexcept;
    static IpAddress fromV6(const in6_addr &addr) noexcept;

    int family() const noexcept { return m_family; }
    bool valid() const noexcept { return m_family != AF_UNSPEC; }
    std::span<const std::byte> octets() const noexcept;
    std::string toString() const;
    bool globallyRoutable() const noexcept;

    friend bool operator==(const IpAddress &, const IpAddress &) = default;

  private:
    int m_family = AF_UNSPEC;
    std::array<std::byte, 16> m_octets{};
};

class IpPrefix {
  public:
    IpPrefix() = default;
    IpPrefix(IpAddress address, unsigned bits) noexcept;

    [[nodiscard]] static std::optional<IpPrefix> parse(std::string_view cidr);

    const IpAddress &address() const noexcept { return m_address; }
    unsigned bits() const noexcept { return m_bits; }
    bool contains(const IpAddress &addr) const noexcept;
    bool isDefaultRoute() const noexcept { return m_bits == 0 && m_address.valid(); }

  private:
    IpAddress m_address;
    unsigned m_bits = 0;
};

class PrefixSet {
  public:
    PrefixSet() = default;

    [[nodiscard]] static PrefixSet parseAll(std::span<const std::string> cidrs);

    void insert(IpPrefix prefix);
    bool contains(const IpAddress &addr) const noexcept;
    bool hasDefaultRoute(int family) const noexcept;
    bool empty() const noexcept { return m_prefixes.empty(); }

  private:
    std::vector<IpPrefix> m_prefixes;
};

class SockAddr {
  public:
    SockAddr(const IpAddress &addr, std::uint16_t port) noexcept;

    const sockaddr *data() const noexcept;
    socklen_t size() const noexcept { return m_size; }

  private:
    sockaddr_storage m_storage{};
    socklen_t m_size = 0;
};

}

#endif // NET_IP_H
