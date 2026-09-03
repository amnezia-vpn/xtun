#include "udp.h"
#include "net/network_order.h"

#include <cstring>

namespace libxtun::net
{
    namespace
    {

        constexpr std::size_t V4_SRC_OFFSET = 12;
        constexpr std::size_t V4_DST_OFFSET = 16;
        constexpr std::size_t V6_SRC_OFFSET = 8;
        constexpr std::size_t V6_DST_OFFSET = 24;
        constexpr std::size_t V4_CHECKSUM_OFFSET = 10;
        constexpr std::size_t UDP_CHECKSUM_OFFSET = 6;
        constexpr std::uint8_t DEFAULT_HOP_LIMIT = 64;

        unsigned octetAt(std::span<const std::byte> packet, std::size_t index) noexcept
        {
            return std::to_integer<unsigned>(packet[index]);
        }

        IpAddress addressAt(std::span<const std::byte> packet, std::size_t offset, bool v6) noexcept
        {
            if (v6) {
                in6_addr addr {};
                std::memcpy(&addr, packet.data() + offset, sizeof(addr));
                return IpAddress::fromV6(addr);
            }
            in_addr addr {};
            std::memcpy(&addr, packet.data() + offset, sizeof(addr));
            return IpAddress::fromV4(addr);
        }

        void appendOctets(std::vector<std::byte> &out, std::span<const std::byte> octets)
        {
            out.insert(out.end(), octets.begin(), octets.end());
        }

        std::uint32_t pseudoHeaderSum(const IpAddress &source, const IpAddress &destination, std::size_t udpLen)
        {
            std::vector<std::byte> header;
            header.reserve(IPV6_HEADER_LEN);

            appendOctets(header, source.octets());
            appendOctets(header, destination.octets());

            if (source.family() == AF_INET6) {
                appendBigEndian32(header, static_cast<std::uint32_t>(udpLen));
                header.push_back(std::byte { 0 });
                header.push_back(std::byte { 0 });
                header.push_back(std::byte { 0 });
                header.push_back(static_cast<std::byte>(IPPROTO_UDP));
            } else {
                header.push_back(std::byte { 0 });
                header.push_back(static_cast<std::byte>(IPPROTO_UDP));
                appendBigEndian16(header, static_cast<std::uint16_t>(udpLen));
            }
            return partialSum(header);
        }

    }

    std::optional<UdpDatagramView> UdpDatagramView::parse(std::span<const std::byte> packet)
    {
        if (packet.empty()) {
            return std::nullopt;
        }

        std::size_t headerLen = 0;
        switch (octetAt(packet, 0) >> 4) {
        case 4: {
            if (packet.size() < IPV4_HEADER_LEN) {
                return std::nullopt;
            }
            headerLen = (octetAt(packet, 0) & 0x0fu) * 4u;
            if (headerLen < IPV4_HEADER_LEN || packet.size() < headerLen) {
                return std::nullopt;
            }
            if (octetAt(packet, 9) != IPPROTO_UDP) {
                return std::nullopt;
            }
            if ((readBigEndian16(packet, 6) & 0x3fffu) != 0) {
                return std::nullopt;
            }
            const std::size_t total = readBigEndian16(packet, 2);
            if (total < headerLen + UDP_HEADER_LEN || total > packet.size()) {
                return std::nullopt;
            }
            break;
        }
        case 6: {
            if (packet.size() < IPV6_HEADER_LEN) {
                return std::nullopt;
            }
            if (octetAt(packet, 6) != IPPROTO_UDP) {
                return std::nullopt;
            }
            const std::size_t payloadLen = readBigEndian16(packet, 4);
            if (payloadLen < UDP_HEADER_LEN || IPV6_HEADER_LEN + payloadLen > packet.size()) {
                return std::nullopt;
            }
            headerLen = IPV6_HEADER_LEN;
            break;
        }
        default: return std::nullopt;
        }

        const std::size_t udpLen = readBigEndian16(packet, headerLen + 4);
        if (udpLen < UDP_HEADER_LEN || headerLen + udpLen > packet.size()) {
            return std::nullopt;
        }

        UdpDatagramView view;
        view.m_packet = packet;
        view.m_headerLen = static_cast<std::uint8_t>(headerLen);
        return view;
    }

    bool UdpDatagramView::isV6() const noexcept
    {
        return (octetAt(m_packet, 0) >> 4) == 6;
    }

    std::uint16_t UdpDatagramView::sourcePort() const noexcept
    {
        return readBigEndian16(m_packet, m_headerLen);
    }

    std::uint16_t UdpDatagramView::destinationPort() const noexcept
    {
        return readBigEndian16(m_packet, m_headerLen + 2);
    }

    IpAddress UdpDatagramView::source() const noexcept
    {
        const bool v6 = isV6();
        return addressAt(m_packet, v6 ? V6_SRC_OFFSET : V4_SRC_OFFSET, v6);
    }

    IpAddress UdpDatagramView::destination() const noexcept
    {
        const bool v6 = isV6();
        return addressAt(m_packet, v6 ? V6_DST_OFFSET : V4_DST_OFFSET, v6);
    }

    std::span<const std::byte> UdpDatagramView::payload() const noexcept
    {
        const std::size_t udpLen = readBigEndian16(m_packet, m_headerLen + 4);
        return m_packet.subspan(m_headerLen + UDP_HEADER_LEN, udpLen - UDP_HEADER_LEN);
    }

    std::vector<std::byte> buildUdpDatagram(const IpAddress &source, const IpAddress &destination,
                                            std::uint16_t sourcePort, std::uint16_t destinationPort,
                                            std::span<const std::byte> payload)
    {
        if (!source.valid() || source.family() != destination.family()) {
            return {};
        }

        const bool v6 = source.family() == AF_INET6;
        const std::size_t ipLen = v6 ? IPV6_HEADER_LEN : IPV4_HEADER_LEN;
        const std::size_t udpLen = UDP_HEADER_LEN + payload.size();

        std::vector<std::byte> out;
        out.reserve(ipLen + udpLen);

        if (v6) {
            out.push_back(std::byte { 0x60 });
            out.push_back(std::byte { 0 });
            appendBigEndian16(out, 0);
            appendBigEndian16(out, static_cast<std::uint16_t>(udpLen));
            out.push_back(static_cast<std::byte>(IPPROTO_UDP));
            out.push_back(static_cast<std::byte>(DEFAULT_HOP_LIMIT));
            appendOctets(out, source.octets());
            appendOctets(out, destination.octets());
        } else {
            out.push_back(std::byte { 0x45 });
            out.push_back(std::byte { 0 });
            appendBigEndian16(out, static_cast<std::uint16_t>(ipLen + udpLen));
            appendBigEndian16(out, 0);
            appendBigEndian16(out, 0);
            out.push_back(static_cast<std::byte>(DEFAULT_HOP_LIMIT));
            out.push_back(static_cast<std::byte>(IPPROTO_UDP));
            appendBigEndian16(out, 0);
            appendOctets(out, source.octets());
            appendOctets(out, destination.octets());
            writeBigEndian16(out, V4_CHECKSUM_OFFSET, internetChecksum({ out.data(), IPV4_HEADER_LEN }));
        }

        appendBigEndian16(out, sourcePort);
        appendBigEndian16(out, destinationPort);
        appendBigEndian16(out, static_cast<std::uint16_t>(udpLen));
        appendBigEndian16(out, 0);
        out.insert(out.end(), payload.begin(), payload.end());

        const std::uint32_t seed = pseudoHeaderSum(source, destination, udpLen);
        std::uint16_t checksum = internetChecksum({ out.data() + ipLen, udpLen }, seed);
        if (checksum == 0) {
            checksum = 0xffff;
        }
        writeBigEndian16(out, ipLen + UDP_CHECKSUM_OFFSET, checksum);

        return out;
    }

    std::uint32_t partialSum(std::span<const std::byte> data, std::uint32_t seed) noexcept
    {
        std::uint32_t sum = seed;
        std::size_t i = 0;
        for (; i + 1 < data.size(); i += 2) {
            sum += (std::to_integer<std::uint32_t>(data[i]) << 8) | std::to_integer<std::uint32_t>(data[i + 1]);
        }
        if (i < data.size()) {
            sum += std::to_integer<std::uint32_t>(data[i]) << 8;
        }
        return sum;
    }

    std::uint16_t internetChecksum(std::span<const std::byte> data, std::uint32_t seed) noexcept
    {
        std::uint32_t sum = partialSum(data, seed);
        while ((sum >> 16) != 0) {
            sum = (sum & 0xffffu) + (sum >> 16);
        }
        return static_cast<std::uint16_t>(~sum & 0xffffu);
    }
}
