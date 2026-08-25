#include "udp.h"

#include "net/network_order.h"

#include <cstring>

namespace libxtun::net {

namespace {

constexpr std::size_t kV4SourceOffset = 12;
constexpr std::size_t kV4DestinationOffset = 16;
constexpr std::size_t kV6SourceOffset = 8;
constexpr std::size_t kV6DestinationOffset = 24;
constexpr std::size_t kV4ChecksumOffset = 10;
constexpr std::size_t kUdpChecksumOffset = 6;
constexpr std::uint8_t kDefaultHopLimit = 64;

unsigned octetAt(std::span<const std::byte> packet, std::size_t index) noexcept {
    return std::to_integer<unsigned>(packet[index]);
}

IpAddress addressAt(std::span<const std::byte> packet, std::size_t offset, bool v6) noexcept {
    if (v6) {
        in6_addr addr{};
        std::memcpy(&addr, packet.data() + offset, sizeof(addr));
        return IpAddress::fromV6(addr);
    }
    in_addr addr{};
    std::memcpy(&addr, packet.data() + offset, sizeof(addr));
    return IpAddress::fromV4(addr);
}

void appendOctets(std::vector<std::byte> &out, std::span<const std::byte> octets) {
    out.insert(out.end(), octets.begin(), octets.end());
}

std::uint32_t pseudoHeaderSum(const IpAddress &source, const IpAddress &destination,
                              std::size_t udp_len) {
    std::vector<std::byte> header;
    header.reserve(kIpv6HeaderLen);

    appendOctets(header, source.octets());
    appendOctets(header, destination.octets());

    if (source.family() == AF_INET6) {
        appendBigEndian32(header, static_cast<std::uint32_t>(udp_len));
        header.push_back(std::byte{0});
        header.push_back(std::byte{0});
        header.push_back(std::byte{0});
        header.push_back(static_cast<std::byte>(IPPROTO_UDP));
    } else {
        header.push_back(std::byte{0});
        header.push_back(static_cast<std::byte>(IPPROTO_UDP));
        appendBigEndian16(header, static_cast<std::uint16_t>(udp_len));
    }
    return partialSum(header);
}

}

std::optional<UdpDatagramView> UdpDatagramView::parse(std::span<const std::byte> packet) {
    if (packet.empty()) {
        return std::nullopt;
    }

    std::size_t header_len = 0;
    switch (octetAt(packet, 0) >> 4) {
        case 4: {
            if (packet.size() < kIpv4HeaderLen) {
                return std::nullopt;
            }
            header_len = (octetAt(packet, 0) & 0x0fu) * 4u;
            if (header_len < kIpv4HeaderLen || packet.size() < header_len) {
                return std::nullopt;
            }
            if (octetAt(packet, 9) != IPPROTO_UDP) {
                return std::nullopt;
            }
            if ((readBigEndian16(packet, 6) & 0x3fffu) != 0) {
                return std::nullopt;
            }
            const std::size_t total = readBigEndian16(packet, 2);
            if (total < header_len + kUdpHeaderLen || total > packet.size()) {
                return std::nullopt;
            }
            break;
        }
        case 6: {
            if (packet.size() < kIpv6HeaderLen) {
                return std::nullopt;
            }
            if (octetAt(packet, 6) != IPPROTO_UDP) {
                return std::nullopt;
            }
            const std::size_t payload_len = readBigEndian16(packet, 4);
            if (payload_len < kUdpHeaderLen || kIpv6HeaderLen + payload_len > packet.size()) {
                return std::nullopt;
            }
            header_len = kIpv6HeaderLen;
            break;
        }
        default:
            return std::nullopt;
    }

    const std::size_t udp_len = readBigEndian16(packet, header_len + 4);
    if (udp_len < kUdpHeaderLen || header_len + udp_len > packet.size()) {
        return std::nullopt;
    }

    UdpDatagramView view;
    view.m_packet = packet;
    view.m_header_len = static_cast<std::uint8_t>(header_len);
    return view;
}

bool UdpDatagramView::isV6() const noexcept {
    return (octetAt(m_packet, 0) >> 4) == 6;
}

std::uint16_t UdpDatagramView::sourcePort() const noexcept {
    return readBigEndian16(m_packet, m_header_len);
}

std::uint16_t UdpDatagramView::destinationPort() const noexcept {
    return readBigEndian16(m_packet, m_header_len + 2);
}

IpAddress UdpDatagramView::source() const noexcept {
    const bool v6 = isV6();
    return addressAt(m_packet, v6 ? kV6SourceOffset : kV4SourceOffset, v6);
}

IpAddress UdpDatagramView::destination() const noexcept {
    const bool v6 = isV6();
    return addressAt(m_packet, v6 ? kV6DestinationOffset : kV4DestinationOffset, v6);
}

std::span<const std::byte> UdpDatagramView::payload() const noexcept {
    const std::size_t udp_len = readBigEndian16(m_packet, m_header_len + 4);
    return m_packet.subspan(m_header_len + kUdpHeaderLen, udp_len - kUdpHeaderLen);
}

std::vector<std::byte> buildUdpDatagram(const IpAddress &source, const IpAddress &destination,
                                        std::uint16_t source_port, std::uint16_t destination_port,
                                        std::span<const std::byte> payload) {
    if (!source.valid() || source.family() != destination.family()) {
        return {};
    }

    const bool v6 = source.family() == AF_INET6;
    const std::size_t ip_len = v6 ? kIpv6HeaderLen : kIpv4HeaderLen;
    const std::size_t udp_len = kUdpHeaderLen + payload.size();

    std::vector<std::byte> out;
    out.reserve(ip_len + udp_len);

    if (v6) {
        out.push_back(std::byte{0x60});
        out.push_back(std::byte{0});
        appendBigEndian16(out, 0);
        appendBigEndian16(out, static_cast<std::uint16_t>(udp_len));
        out.push_back(static_cast<std::byte>(IPPROTO_UDP));
        out.push_back(static_cast<std::byte>(kDefaultHopLimit));
        appendOctets(out, source.octets());
        appendOctets(out, destination.octets());
    } else {
        out.push_back(std::byte{0x45});
        out.push_back(std::byte{0});
        appendBigEndian16(out, static_cast<std::uint16_t>(ip_len + udp_len));
        appendBigEndian16(out, 0);
        appendBigEndian16(out, 0);
        out.push_back(static_cast<std::byte>(kDefaultHopLimit));
        out.push_back(static_cast<std::byte>(IPPROTO_UDP));
        appendBigEndian16(out, 0);
        appendOctets(out, source.octets());
        appendOctets(out, destination.octets());
        writeBigEndian16(out, kV4ChecksumOffset,
                         internetChecksum({out.data(), kIpv4HeaderLen}));
    }

    appendBigEndian16(out, source_port);
    appendBigEndian16(out, destination_port);
    appendBigEndian16(out, static_cast<std::uint16_t>(udp_len));
    appendBigEndian16(out, 0);
    out.insert(out.end(), payload.begin(), payload.end());

    const std::uint32_t seed = pseudoHeaderSum(source, destination, udp_len);
    std::uint16_t checksum = internetChecksum({out.data() + ip_len, udp_len}, seed);
    if (checksum == 0) {
        checksum = 0xffff;
    }
    writeBigEndian16(out, ip_len + kUdpChecksumOffset, checksum);

    return out;
}

std::uint32_t partialSum(std::span<const std::byte> data, std::uint32_t seed) noexcept {
    std::uint32_t sum = seed;
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += (std::to_integer<std::uint32_t>(data[i]) << 8) |
               std::to_integer<std::uint32_t>(data[i + 1]);
    }
    if (i < data.size()) {
        sum += std::to_integer<std::uint32_t>(data[i]) << 8;
    }
    return sum;
}

std::uint16_t internetChecksum(std::span<const std::byte> data, std::uint32_t seed) noexcept {
    std::uint32_t sum = partialSum(data, seed);
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xffffu);
}

}
