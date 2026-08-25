#ifndef NET_UDP_H
#define NET_UDP_H

#include "net/ip.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace libxtun::net {

inline constexpr std::size_t kIpv4HeaderLen = 20;
inline constexpr std::size_t kIpv6HeaderLen = 40;
inline constexpr std::size_t kUdpHeaderLen = 8;

class UdpDatagramView {
  public:
    [[nodiscard]] static std::optional<UdpDatagramView> parse(std::span<const std::byte> packet);

    std::uint16_t sourcePort() const noexcept;
    std::uint16_t destinationPort() const noexcept;
    IpAddress source() const noexcept;
    IpAddress destination() const noexcept;
    std::span<const std::byte> payload() const noexcept;

  private:
    UdpDatagramView() = default;

    bool isV6() const noexcept;

    std::span<const std::byte> m_packet;
    std::uint8_t m_header_len = 0;
};

std::vector<std::byte> buildUdpDatagram(const IpAddress &source, const IpAddress &destination,
                                        std::uint16_t source_port, std::uint16_t destination_port,
                                        std::span<const std::byte> payload);

std::uint32_t partialSum(std::span<const std::byte> data, std::uint32_t seed = 0) noexcept;
std::uint16_t internetChecksum(std::span<const std::byte> data, std::uint32_t seed = 0) noexcept;

}

#endif // NET_UDP_H
