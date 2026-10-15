#include "dns_query.h"

#include "net/network_order.h"
#include "util/random.h"

#include <cstring>
#include <string_view>

namespace libxtun::health
{
    namespace
    {
        constexpr std::size_t DNS_HEADER_LEN = 12;

        constexpr std::string_view PROBE_DOMAIN = "example.com";
        constexpr std::uint16_t DNS_TYPE_A = 1;
        constexpr std::uint16_t DNS_CLASS_IN = 1;
        constexpr int NONCE_HEX_DIGITS = 8;
        constexpr std::string_view HEX_DIGITS = "0123456789abcdef";

        class DnsFlags
        {
        public:
            static constexpr std::uint16_t STANDARD_QUERY = 0x0100;

            explicit DnsFlags(std::uint16_t raw) noexcept : m_raw(raw)
            {
            }

            bool isResponse() const noexcept
            {
                return (m_raw & 0x8000u) != 0;
            }
            unsigned opcode() const noexcept
            {
                return (m_raw >> 11) & 0x0fu;
            }
            unsigned rcode() const noexcept
            {
                return m_raw & 0x0fu;
            }

        private:
            std::uint16_t m_raw;
        };

        constexpr unsigned OPCODE_QUERY = 0;
        constexpr unsigned RCODE_NO_ERROR = 0;
        constexpr unsigned RCODE_NX_DOMAIN = 3;

        void appendNonceLabel(std::vector<std::byte> &out, std::uint32_t nonce)
        {
            out.push_back(static_cast<std::byte>(NONCE_HEX_DIGITS));
            for (int digit = NONCE_HEX_DIGITS - 1; digit >= 0; --digit) {
                const auto nibble = (nonce >> (digit * 4)) & 0xfu;
                out.push_back(static_cast<std::byte>(HEX_DIGITS[nibble]));
            }
        }

        void appendLabels(std::vector<std::byte> &out, std::string_view domain)
        {
            std::size_t start = 0;
            for (;;) {
                const std::size_t dot = domain.find('.', start);
                const std::string_view label = domain.substr(start, dot == std::string_view::npos ? dot : dot - start);
                out.push_back(static_cast<std::byte>(label.size()));
                for (char c : label) {
                    out.push_back(static_cast<std::byte>(c));
                }
                if (dot == std::string_view::npos) {
                    return;
                }
                start = dot + 1;
            }
        }

    }

    DnsQuery::DnsQuery(std::uint16_t transactionId, std::uint32_t nonce)
    {
        m_bytes.reserve(DNS_HEADER_LEN + NONCE_HEX_DIGITS + PROBE_DOMAIN.size() + 8);

        net::appendBigEndian16(m_bytes, transactionId);
        net::appendBigEndian16(m_bytes, DnsFlags::STANDARD_QUERY);
        // QDCOUNT
        net::appendBigEndian16(m_bytes, 1);
        // ANCOUNT
        net::appendBigEndian16(m_bytes, 0);
        // NSCOUNT
        net::appendBigEndian16(m_bytes, 0);
        // ARCOUNT
        net::appendBigEndian16(m_bytes, 0);

        appendNonceLabel(m_bytes, nonce);
        appendLabels(m_bytes, PROBE_DOMAIN);
        m_bytes.push_back(std::byte { 0 });

        net::appendBigEndian16(m_bytes, DNS_TYPE_A);
        net::appendBigEndian16(m_bytes, DNS_CLASS_IN);
    }

    DnsQueryFactory::DnsQueryFactory() noexcept
    {
    }

    DnsQuery DnsQueryFactory::next()
    {
        const std::uint16_t transactionId = rand::next16();
        const std::uint32_t nonce = rand::next32();
        return DnsQuery(transactionId, nonce);
    }
}
