#ifndef TCP_H
#define TCP_H

#include "net/ip.h"
#include "net/view.h"
#include <cstddef>
#include <span>
#include <type_traits>

namespace libxtun::net
{
    // NOLINTBEGIN(readability-identifier-naming)
    namespace TcpFlag
    {
        inline constexpr uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10, URG = 0x20, ECE = 0x40,
                                 CWR = 0x80;
    }
    // NOLINTEND(readability-identifier-naming)

    template<typename T> class TcpRefT
    {
    public:
        static constexpr std::size_t HEADER_LEN = 20;
        explicit TcpRefT(std::span<T, HEADER_LEN> bytes) : m_bytes(bytes)
        {
        }
        operator TcpRefT<const T>() const noexcept
            requires(!std::is_const_v<T>)
        {
            return TcpRefT<const T> { m_bytes };
        }

        uint16_t sport() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[0]) << 8 | std::to_integer<uint16_t>(m_bytes[1]);
        }
        uint16_t dport() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[2]) << 8 | std::to_integer<uint16_t>(m_bytes[3]);
        }
        uint32_t seqNumber() const noexcept
        {
            return std::to_integer<uint32_t>(m_bytes[4]) << 24 | std::to_integer<uint32_t>(m_bytes[5]) << 16
                    | std::to_integer<uint32_t>(m_bytes[6]) << 8 | std::to_integer<uint32_t>(m_bytes[7]);
        }
        uint32_t ackNumber() const noexcept
        {
            return std::to_integer<uint32_t>(m_bytes[8]) << 24 | std::to_integer<uint32_t>(m_bytes[9]) << 16
                    | std::to_integer<uint32_t>(m_bytes[10]) << 8 | std::to_integer<uint32_t>(m_bytes[11]);
        }
        uint8_t dataOffset() const noexcept
        {
            return std::to_integer<uint8_t>(m_bytes[12]) >> 4;
        }
        uint8_t reserved() const noexcept
        {
            return std::to_integer<uint8_t>(m_bytes[12]) & 0xF;
        }
        uint8_t flags() const noexcept
        {
            return std::to_integer<uint8_t>(m_bytes[13]);
        }
        uint16_t window() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[14]) << 8 | std::to_integer<uint16_t>(m_bytes[15]);
        }
        uint16_t checksum() const noexcept
        {
            uint16_t val;
            std::memcpy(&val, &m_bytes[16], 2);
            return val;
        }
        uint16_t urgp() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[18]) << 8 | std::to_integer<uint16_t>(m_bytes[19]);
        }

        TcpRefT &setSport(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[0] = static_cast<std::byte>(val >> 8);
            m_bytes[1] = static_cast<std::byte>(val);
            return *this;
        }
        TcpRefT &setDport(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[2] = static_cast<std::byte>(val >> 8);
            m_bytes[3] = static_cast<std::byte>(val);
            return *this;
        }
        TcpRefT &setSeqNumber(uint32_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[4] = static_cast<std::byte>(val >> 24);
            m_bytes[5] = static_cast<std::byte>(val >> 16);
            m_bytes[6] = static_cast<std::byte>(val >> 8);
            m_bytes[7] = static_cast<std::byte>(val);
            return *this;
        }
        TcpRefT &setAckNumber(uint32_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[8] = static_cast<std::byte>(val >> 24);
            m_bytes[9] = static_cast<std::byte>(val >> 16);
            m_bytes[10] = static_cast<std::byte>(val >> 8);
            m_bytes[11] = static_cast<std::byte>(val);
            return *this;
        }
        TcpRefT &setDataOffset(uint8_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[12] = (m_bytes[12] & static_cast<std::byte>(0xF)) | static_cast<std::byte>(val << 4);
            return *this;
        }
        TcpRefT &setReserved(uint8_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[12] = (m_bytes[12] & static_cast<std::byte>(0xF0)) | static_cast<std::byte>(val & 0xF);
            return *this;
        }
        TcpRefT &setFlags(uint8_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[13] = static_cast<std::byte>(val);
            return *this;
        }
        TcpRefT &setWindow(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[14] = static_cast<std::byte>(val >> 8);
            m_bytes[15] = static_cast<std::byte>(val);
            return *this;
        }
        TcpRefT &setChecksum(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            std::memcpy(&m_bytes[16], &val, 2);
            return *this;
        }
        TcpRefT &setUrgp(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[18] = static_cast<std::byte>(val >> 8);
            m_bytes[19] = static_cast<std::byte>(val);
            return *this;
        }

        TcpRefT &recalcChecksum(IpView ip, std::span<const std::byte> payload)
            requires(!std::is_const_v<T>)
        {
            setChecksum(0);
            Checksum cs;
            cs.update(ip.src());
            cs.update(ip.dst());
            uint8_t zeroes = static_cast<uint8_t>(0);
            cs.update(&zeroes, 1);
            uint8_t proto = ip.protocol();
            cs.update(&proto, 1);
            uint16_t tcpLen = htons(m_bytes.size_bytes() + payload.size_bytes());
            cs.update(&tcpLen, 2);
            cs.update(m_bytes.data(), m_bytes.size_bytes());
            cs.update(payload.data(), payload.size_bytes());
            uint16_t check = cs.finalize();
            setChecksum(check == 0 ? 0xFFFF : check);
            return *this;
        }
        TcpRefT &recalcChecksum(Ip6View ip, std::span<const std::byte> payload)
            requires(!std::is_const_v<T>)
        {
            setChecksum(0);
            Checksum cs;
            cs.update(ip.src());
            cs.update(ip.dst());
            uint32_t tcpLen = htonl(m_bytes.size_bytes() + payload.size_bytes());
            cs.update(&tcpLen, 4);
            uint8_t pseudoTail[4] = { 0, 0, 0, ip.nextHeader() };
            cs.update(pseudoTail, 4);
            cs.update(m_bytes.data(), m_bytes.size_bytes());
            cs.update(payload.data(), payload.size_bytes());
            uint16_t check = cs.finalize();
            setChecksum(check == 0 ? 0xFFFF : check);
            return *this;
        }

    private:
        std::span<T, HEADER_LEN> m_bytes;
    };
    using TcpRef = TcpRefT<std::byte>;
    static_assert(BasicRef<TcpRef>);
    using TcpView = TcpRefT<const std::byte>;
    static_assert(BasicView<TcpView>);
}

#endif
