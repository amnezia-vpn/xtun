#ifndef NET_UDP_H
#define NET_UDP_H

#include "net/checksum.h"
#include "net/ip.h"
#include "net/view.h"
#include <cstddef>
#include <span>

namespace libxtun::net
{
    template<typename T> class UdpRefT
    {
    public:
        static constexpr std::size_t HEADER_LEN = 8;
        explicit UdpRefT(std::span<T, HEADER_LEN> bytes) : m_bytes(bytes)
        {
        }

        uint16_t sport() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[0]) << 8 | std::to_integer<uint16_t>(m_bytes[1]);
        }
        uint16_t dport() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[2]) << 8 | std::to_integer<uint16_t>(m_bytes[3]);
        }
        uint16_t length() const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[4]) << 8 | std::to_integer<uint16_t>(m_bytes[5]);
        }
        uint16_t checksum() const noexcept
        {
            uint16_t val;
            std::memcpy(&val, &m_bytes[6], 2);
            return val;
        }

        UdpRefT &setSport(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[0] = static_cast<std::byte>(val >> 8);
            m_bytes[1] = static_cast<std::byte>(val);
            return *this;
        }
        UdpRefT &setDport(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[2] = static_cast<std::byte>(val >> 8);
            m_bytes[3] = static_cast<std::byte>(val);
            return *this;
        }
        UdpRefT &setLength(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[4] = static_cast<std::byte>(val >> 8);
            m_bytes[5] = static_cast<std::byte>(val);
            return *this;
        }
        UdpRefT &setChecksum(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            std::memcpy(&m_bytes[6], &val, 2);
            return *this;
        }

        UdpRefT &recalcChecksum(IpView ip, std::span<const std::byte> payload)
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
            uint16_t udpLen = htons(m_bytes.size_bytes() + payload.size_bytes());
            cs.update(&udpLen, 2);
            cs.update(m_bytes.data(), m_bytes.size_bytes());
            cs.update(payload.data(), payload.size_bytes());
            uint16_t check = cs.finalize();
            setChecksum(check == 0 ? 0xFFFF : check);
            return *this;
        }
        UdpRefT &recalcChecksum(Ip6View ip, std::span<const std::byte> payload)
            requires(!std::is_const_v<T>)
        {
            setChecksum(0);
            Checksum cs;
            cs.update(ip.src());
            cs.update(ip.dst());
            uint32_t udpLen = htonl(m_bytes.size_bytes() + payload.size_bytes());
            cs.update(&udpLen, 4);
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
    using UdpRef = UdpRefT<std::byte>;
    static_assert(BasicRef<UdpRef>);
    using UdpView = UdpRefT<const std::byte>;
    static_assert(BasicView<UdpView>);
}

#endif // NET_UDP_H
