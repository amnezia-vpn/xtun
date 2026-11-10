#ifndef NET_IP_H
#define NET_IP_H

#include "net/checksum.h"
#include "net/sys.h" // IWYU pragma: keep

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace libxtun::net
{
    int ipv6L4Offset(const void *b, int n, uint8_t &proto);

    class IpAddress
    {
    public:
        IpAddress() = default;

        [[nodiscard]] static std::optional<IpAddress> parse(std::string_view text);
        static IpAddress fromV4(const in_addr &addr) noexcept;
        static IpAddress fromV6(const in6_addr &addr) noexcept;

        int family() const noexcept
        {
            return m_family;
        }
        bool valid() const noexcept
        {
            return m_family != AF_UNSPEC;
        }
        std::span<const std::byte> octets() const noexcept;
        std::string toString() const;
        bool globallyRoutable() const noexcept;

        friend bool operator==(const IpAddress &, const IpAddress &) = default;

    private:
        int m_family = AF_UNSPEC;
        std::array<std::byte, 16> m_octets {};
    };

    class IpPrefix
    {
    public:
        IpPrefix() = default;
        IpPrefix(IpAddress address, unsigned bits) noexcept;

        [[nodiscard]] static std::optional<IpPrefix> parse(std::string_view cidr);

        const IpAddress &address() const noexcept
        {
            return m_address;
        }
        unsigned bits() const noexcept
        {
            return m_bits;
        }
        bool contains(const IpAddress &addr) const noexcept;
        bool isDefaultRoute() const noexcept
        {
            return m_bits == 0 && m_address.valid();
        }
        IpPrefix network() const noexcept;
        std::string toString() const;

        friend bool operator==(const IpPrefix &, const IpPrefix &) = default;

    private:
        IpAddress m_address;
        unsigned m_bits = 0;
    };

    class PrefixSet
    {
    public:
        PrefixSet() = default;

        [[nodiscard]] static PrefixSet parseAll(std::span<const std::string> cidrs);

        void insert(IpPrefix prefix);
        bool contains(const IpAddress &addr) const noexcept;
        bool hasDefaultRoute(int family) const noexcept;
        bool empty() const noexcept
        {
            return m_prefixes.empty();
        }

    private:
        std::vector<IpPrefix> m_prefixes;
    };

    class SockAddr
    {
    public:
        SockAddr(const IpAddress &addr, std::uint16_t port) noexcept;

        const sockaddr *data() const noexcept;
        socklen_t size() const noexcept
        {
            return m_size;
        }

    private:
        sockaddr_storage m_storage {};
        socklen_t m_size = 0;
    };

    template<typename B> class IpRefT
    {
    public:
        static constexpr std::size_t HEADER_LEN = 20;
        explicit IpRefT(std::span<B, HEADER_LEN> bytes) : m_bytes(bytes)
        {
        }
        operator IpRefT<const B>() const noexcept
            requires(!std::is_const_v<B>)
        {
            return IpRefT<const B> { m_bytes };
        }

        uint8_t version() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[0]) >> 4;
        }
        uint8_t ihl() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[0]) & 0xF;
        }
        std::size_t ihlBytes() const noexcept
        {
            return ihl() * 4;
        }
        uint8_t dscp() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[1]) >> 2;
        }
        uint8_t ecn() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[1]) & 0x3;
        }
        uint16_t totalLen() const noexcept
        {
            return static_cast<uint16_t>(m_bytes[2]) << 8 | static_cast<uint16_t>(m_bytes[3]);
        }
        uint16_t identification() const noexcept
        {
            return static_cast<uint16_t>(m_bytes[4]) << 8 | static_cast<uint16_t>(m_bytes[5]);
        }
        uint8_t flags() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[6]) >> 5;
        }
        uint16_t fragmentOffset() const noexcept
        {
            return (static_cast<uint16_t>(m_bytes[6]) & 0x1F) << 8 | static_cast<uint16_t>(m_bytes[7]);
        }
        uint8_t ttl() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[8]);
        }
        uint8_t protocol() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[9]);
        }
        uint16_t checksum() const noexcept
        {
            uint16_t val;
            std::memcpy(&val, &m_bytes[10], 2);
            return val;
        }
        std::span<B, 4> src() const noexcept
        {
            return m_bytes.template subspan<12, 4>();
        }
        IpAddress srcAddress() const noexcept
        {
            in_addr addr;
            std::memcpy(&addr, &m_bytes[12], 4);
            return IpAddress::fromV4(addr);
        }
        std::span<B, 4> dst() const noexcept
        {
            return m_bytes.template subspan<16, 4>();
        }
        IpAddress dstAddress() const noexcept
        {
            in_addr addr;
            std::memcpy(&addr, &m_bytes[16], 4);
            return IpAddress::fromV4(addr);
        }

        IpRefT &setVersion(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[0] = (m_bytes[0] & static_cast<std::byte>(0xF)) | (static_cast<std::byte>(val << 4));
            return *this;
        }
        IpRefT &setIhl(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[0] = (m_bytes[0] & static_cast<std::byte>(0xF0)) | (static_cast<std::byte>(val & 0xF));
            return *this;
        }
        IpRefT &setIhlBytes(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            assert(val % 4 == 0);
            return setIhl(val / 4);
        }
        IpRefT &setDscp(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[1] = (m_bytes[1] & static_cast<std::byte>(0x3)) | (static_cast<std::byte>(val << 2));
            return *this;
        }
        IpRefT &setEcn(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[1] = (m_bytes[1] & static_cast<std::byte>(0xFC)) | (static_cast<std::byte>(val & 0x3));
            return *this;
        }
        IpRefT &setTotalLen(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[2] = static_cast<std::byte>(val >> 8);
            m_bytes[3] = static_cast<std::byte>(val);
            return *this;
        }
        IpRefT &setIdentification(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[4] = static_cast<std::byte>(val >> 8);
            m_bytes[5] = static_cast<std::byte>(val);
            return *this;
        }
        IpRefT &setFlags(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[6] = (m_bytes[6] & static_cast<std::byte>(0x1F)) | static_cast<std::byte>(val << 5);
            return *this;
        }
        IpRefT &setFragOffset(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[6] = (m_bytes[6] & static_cast<std::byte>(0xE0)) | static_cast<std::byte>((val >> 8) & 0x1F);
            m_bytes[7] = static_cast<std::byte>(val);
            return *this;
        }
        IpRefT &setTtl(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[8] = static_cast<std::byte>(val);
            return *this;
        }
        IpRefT &setProtocol(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[9] = static_cast<std::byte>(val);
            return *this;
        }
        IpRefT &setChecksum(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            std::memcpy(&m_bytes[10], &val, 2);
            return *this;
        }
        IpRefT &setSrc(std::span<const std::byte, 4> val)
            requires(!std::is_const_v<B>)
        {
            std::memcpy(&m_bytes[12], val.data(), 4);
            return *this;
        }
        IpRefT &setSrcAddress(IpAddress val) noexcept
            requires(!std::is_const_v<B>)
        {
            assert(val.octets().size() == 4);
            std::memcpy(&m_bytes[12], val.octets().data(), 4);
            return *this;
        }
        IpRefT &setDst(std::span<const std::byte, 4> val)
            requires(!std::is_const_v<B>)
        {
            std::memcpy(&m_bytes[16], val.data(), 4);
            return *this;
        }
        IpRefT &setDstAddress(IpAddress val) noexcept
            requires(!std::is_const_v<B>)
        {
            assert(val.octets().size() == 4);
            std::memcpy(&m_bytes[16], val.octets().data(), 4);
            return *this;
        }

        IpRefT &recalcChecksum(std::span<const std::byte> opts = {}) noexcept
            requires(!std::is_const_v<B>)
        {
            setChecksum(0);
            Checksum cs;
            cs.update(m_bytes.data(), HEADER_LEN);
            cs.update(opts.data(), opts.size_bytes());
            setChecksum(cs.finalize());
            return *this;
        }

    private:
        std::span<B, HEADER_LEN> m_bytes;
    };
    using IpRef = IpRefT<std::byte>;
    using IpView = IpRefT<const std::byte>;

    template<typename B> class Ip6RefT
    {
    public:
        static constexpr std::size_t HEADER_LEN = 40;
        explicit Ip6RefT(std::span<B, HEADER_LEN> bytes) : m_bytes(bytes)
        {
        }
        operator Ip6RefT<const B>() const noexcept
            requires(!std::is_const_v<B>)
        {
            return Ip6RefT<const B> { m_bytes };
        }

        uint8_t version() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[0]) >> 4;
        }
        uint8_t trafficClass() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[0]) << 4 | static_cast<uint8_t>(m_bytes[1]) >> 4;
        }
        uint32_t flowLabel() const noexcept
        {
            return (static_cast<uint32_t>(m_bytes[1]) & 0xF) << 16 | static_cast<uint32_t>(m_bytes[2]) << 8
                    | static_cast<uint32_t>(m_bytes[3]);
        }
        uint16_t payloadLength() const noexcept
        {
            return static_cast<uint16_t>(m_bytes[4]) << 8 | static_cast<uint16_t>(m_bytes[5]);
        }
        uint8_t nextHeader() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[6]);
        }
        uint8_t hopLimit() const noexcept
        {
            return static_cast<uint8_t>(m_bytes[7]);
        }
        std::span<const std::byte, 16> src() const noexcept
        {
            return m_bytes.template subspan<8, 16>();
        }
        IpAddress srcAddress() const noexcept
        {
            in6_addr addr;
            std::memcpy(&addr, &m_bytes[8], 16);
            return IpAddress::fromV6(addr);
        }
        std::span<const std::byte, 16> dst() const noexcept
        {
            return m_bytes.template subspan<24, 16>();
        }
        IpAddress dstAddress() const noexcept
        {
            in6_addr addr;
            std::memcpy(&addr, &m_bytes[24], 16);
            return IpAddress::fromV6(addr);
        }

        Ip6RefT &setVersion(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[0] = (m_bytes[0] & static_cast<std::byte>(0xF)) | static_cast<std::byte>(val << 4);
            return *this;
        }
        Ip6RefT &setTrafficClass(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[0] = (m_bytes[0] & static_cast<std::byte>(0xF0)) | static_cast<std::byte>(val >> 4);
            m_bytes[1] = (m_bytes[1] & static_cast<std::byte>(0xF)) | static_cast<std::byte>(val << 4);
            return *this;
        }
        Ip6RefT &setFlowLabel(uint32_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[1] = (m_bytes[1] & static_cast<std::byte>(0xF0)) | static_cast<std::byte>((val >> 16) & 0xF);
            m_bytes[2] = static_cast<std::byte>(val >> 8);
            m_bytes[3] = static_cast<std::byte>(val);
            return *this;
        }
        Ip6RefT &setPayloadLength(uint16_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[4] = static_cast<std::byte>(val >> 8);
            m_bytes[5] = static_cast<std::byte>(val);
            return *this;
        }
        Ip6RefT &setNextHeader(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[6] = static_cast<std::byte>(val);
            return *this;
        }
        Ip6RefT &setHopLimit(uint8_t val) noexcept
            requires(!std::is_const_v<B>)
        {
            m_bytes[7] = static_cast<std::byte>(val);
            return *this;
        }
        Ip6RefT &setSrc(std::span<const std::byte, 16> val)
            requires(!std::is_const_v<B>)
        {
            std::memcpy(&m_bytes[8], val.data(), val.size_bytes());
            return *this;
        }
        Ip6RefT &setSrcAddress(IpAddress val) noexcept
            requires(!std::is_const_v<B>)
        {
            assert(val.octets().size() == 16);
            std::memcpy(&m_bytes[8], val.octets().data(), 16);
            return *this;
        }
        Ip6RefT &setDst(std::span<const std::byte, 16> val)
            requires(!std::is_const_v<B>)
        {
            std::memcpy(&m_bytes[24], val.data(), val.size_bytes());
            return *this;
        }
        Ip6RefT &setDstAddress(IpAddress val) noexcept
            requires(!std::is_const_v<B>)
        {
            assert(val.octets().size() == 16);
            std::memcpy(&m_bytes[24], val.octets().data(), 16);
            return *this;
        }

    private:
        std::span<B, HEADER_LEN> m_bytes;
    };
    using Ip6Ref = Ip6RefT<std::byte>;
    using Ip6View = Ip6RefT<const std::byte>;
}

#endif // NET_IP_H
