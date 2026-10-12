#ifndef ICMP_H
#define ICMP_H

#include "net/checksum.h"
#include "net/ip.h"
#include <cstddef>
#include <span>
#include <type_traits>

#ifdef _WIN32
    #include <winsock2.h>
    #include <iphlpapi.h>
    
    #define ICMP_MAXTYPE   ICMP4_MASK_REPLY
    #define ICMP_ECHOREPLY ICMP4_ECHO_REPLY
    #define ICMP_ECHO      ICMP4_ECHO_REQUEST
    #define ICMP_UNREACH   ICMP4_DST_UNREACH
    #define ICMP_TIMXCEED  ICMP4_TIME_EXCEEDED
#else
    #include <netinet/icmp6.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
#endif

namespace libxtun::net
{
    template<typename B, int T = ICMP_MAXTYPE> class IcmpRefT
    {
    public:
        static constexpr std::size_t HEADER_LEN = 8;
        IcmpRefT(std::span<B, HEADER_LEN> bytes) : m_bytes(bytes)
        {
        }

        uint8_t type() const noexcept
        {
            return std::to_integer<uint8_t>(m_bytes[0]);
        }
        uint8_t code()
        {
            return std::to_integer<uint8_t>(m_bytes[1]);
        }
        uint16_t checksum()
        {
            uint16_t val;
            std::memcpy(&val, &m_bytes[2], 2);
            return val;
        }
        uint16_t identifier()
            requires((T == ICMP_ECHO || T == ICMP_ECHOREPLY || T == ICMP6_ECHO_REQUEST || T == ICMP6_ECHO_REPLY))
        {
            return std::to_integer<uint16_t>(m_bytes[4]) << 8 | std::to_integer<uint16_t>(m_bytes[5]);
        }
        uint16_t seqNumber()
            requires((T == ICMP_ECHO || T == ICMP_ECHOREPLY || T == ICMP6_ECHO_REQUEST || T == ICMP6_ECHO_REPLY))
        {
            return std::to_integer<uint16_t>(m_bytes[6]) << 8 | std::to_integer<uint16_t>(m_bytes[7]);
        }

        IcmpRefT &setType(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[0] = static_cast<std::byte>(val);
            return *this;
        }
        IcmpRefT &setCode(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[1] = static_cast<std::byte>(val);
            return *this;
        }
        IcmpRefT &setChecksum(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            std::memcpy(&m_bytes[2], &val, 2);
            return *this;
        }
        IcmpRefT &setIdentifier(uint16_t val)
            requires(!std::is_const_v<B>
                     && (T == ICMP_ECHO || T == ICMP_ECHOREPLY || T == ICMP6_ECHO_REQUEST || T == ICMP6_ECHO_REPLY))
        {
            m_bytes[4] = static_cast<std::byte>(val >> 8);
            m_bytes[5] = static_cast<std::byte>(val);
            return *this;
        }
        IcmpRefT &setSeqNumber(uint16_t val)
            requires(!std::is_const_v<B>
                     && (T == ICMP_ECHO || T == ICMP_ECHOREPLY || T == ICMP6_ECHO_REQUEST || T == ICMP6_ECHO_REPLY))
        {
            m_bytes[6] = static_cast<std::byte>(val >> 8);
            m_bytes[7] = static_cast<std::byte>(val);
            return *this;
        }

        IcmpRefT &recalcChecksum(IpView ip, std::span<const std::byte> payload)
            requires(!std::is_const_v<B>)
        {
            setChecksum(0);
            Checksum cs;
            cs.update(m_bytes.data(), m_bytes.size_bytes());
            cs.update(payload.data(), payload.size_bytes());
            setChecksum(cs.finalize());
            return *this;
        }
        IcmpRefT &recalcChecksum(Ip6View ip6, std::span<const std::byte> payload)
            requires(!std::is_const_v<B>)
        {
            setChecksum(0);
            Checksum cs;
            cs.update(ip6.src());
            cs.update(ip6.dst());
            uint32_t len = htonl(payload.size_bytes() + m_bytes.size_bytes());
            cs.update(&len, sizeof(len));
            uint8_t pseudoTail[4] = { 0, 0, 0, ip6.nextHeader() };
            cs.update(pseudoTail, 4);
            cs.update(m_bytes.data(), m_bytes.size_bytes());
            cs.update(payload.data(), payload.size_bytes());
            setChecksum(cs.finalize());
            return *this;
        }

    private:
        std::span<B, HEADER_LEN> m_bytes;
    };
    template<int T> using IcmpRef = IcmpRefT<std::byte, T>;
    template<int T> using IcmpView = IcmpRefT<const std::byte, T>;
    using IcmpEchoRef = IcmpRef<ICMP_ECHO>;
    using IcmpEchoView = IcmpView<ICMP_ECHO>;
    using IcmpEchoReplyRef = IcmpRef<ICMP_ECHOREPLY>;
    using IcmpEchoReplyView = IcmpView<ICMP_ECHOREPLY>;
    using Icmp6EchoRef = IcmpRef<ICMP6_ECHO_REQUEST>;
    using Icmp6EchoView = IcmpView<ICMP6_ECHO_REQUEST>;
    using Icmp6EchoReplyRef = IcmpRef<ICMP6_ECHO_REPLY>;
    using Icmp6EchoReplyView = IcmpView<ICMP6_ECHO_REPLY>;
}

#endif
