#ifndef NET_DNS_H
#define NET_DNS_H

#include "net/ip.h"
#include "net/network_order.h"
#include "net/view.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

namespace libxtun::net
{
    // NOLINTBEGIN(readability-identifier-naming)
    namespace DnsFlag
    {
        inline constexpr uint16_t RESPONSE = 0x8000, RECURSION_DESIRED = 0x0100, RECURSION_AVAILABLE = 0x0080;
    }

    namespace DnsType
    {
        inline constexpr uint16_t A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16, AAAA = 28;
    }

    namespace DnsClass
    {
        inline constexpr uint16_t INTERNET = 1, CHAOS = 3, HESIOD = 4;
    }
    // NOLINTEND(readability-identifier-naming)

    template<typename T> class DnsRefT
    {
    public:
        static constexpr std::size_t HEADER_LEN = 12;
        explicit DnsRefT(std::span<T, HEADER_LEN> bytes) : m_bytes(bytes)
        {
        }

        uint16_t id() const noexcept
        {
            return field(0);
        }
        uint16_t flags() const noexcept
        {
            return field(2);
        }
        uint16_t questions() const noexcept
        {
            return field(4);
        }
        uint16_t answers() const noexcept
        {
            return field(6);
        }
        uint16_t authorities() const noexcept
        {
            return field(8);
        }
        uint16_t additionals() const noexcept
        {
            return field(10);
        }

        DnsRefT &setId(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            return setField(0, val);
        }
        DnsRefT &setFlags(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            return setField(2, val);
        }
        DnsRefT &setQuestions(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            return setField(4, val);
        }
        DnsRefT &setAnswers(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            return setField(6, val);
        }
        DnsRefT &setAuthorities(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            return setField(8, val);
        }
        DnsRefT &setAdditionals(uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            return setField(10, val);
        }

    private:
        uint16_t field(std::size_t offset) const noexcept
        {
            return std::to_integer<uint16_t>(m_bytes[offset]) << 8 | std::to_integer<uint16_t>(m_bytes[offset + 1]);
        }
        DnsRefT &setField(std::size_t offset, uint16_t val) noexcept
            requires(!std::is_const_v<T>)
        {
            m_bytes[offset] = static_cast<std::byte>(val >> 8);
            m_bytes[offset + 1] = static_cast<std::byte>(val);
            return *this;
        }

        std::span<T, HEADER_LEN> m_bytes;
    };
    using DnsRef = DnsRefT<std::byte>;
    static_assert(BasicRef<DnsRef>);
    using DnsView = DnsRefT<const std::byte>;
    static_assert(BasicView<DnsView>);

    struct DnsQuestion
    {
        uint16_t type;
        std::size_t end;

        [[nodiscard]] static std::optional<DnsQuestion> parse(std::span<const std::byte> message)
        {
            const std::size_t tailLen = 2 * sizeof(uint16_t);

            std::size_t at = DnsView::HEADER_LEN;
            while (at < message.size() && message[at] != std::byte { 0 }) {
                at += std::to_integer<std::size_t>(message[at]) + 1;
            }

            const std::size_t typeAt = at + 1;
            if (typeAt + tailLen > message.size()) {
                return std::nullopt;
            }
            return DnsQuestion { readBigEndian16(message, typeAt), typeAt + tailLen };
        }
    };

    struct DnsARecord
    {
        uint32_t ttlSeconds;
        IpAddress address;

        void appendTo(std::vector<std::byte> &message) const
        {
            const auto questionName = static_cast<uint16_t>(0xc000 | DnsView::HEADER_LEN);
            const auto octets = address.octets();

            appendBigEndian16(message, questionName);
            appendBigEndian16(message, DnsType::A);
            appendBigEndian16(message, DnsClass::INTERNET);
            appendBigEndian32(message, ttlSeconds);
            appendBigEndian16(message, static_cast<uint16_t>(octets.size()));
            message.insert(message.end(), octets.begin(), octets.end());
        }
    };
}

#endif // NET_DNS_H
