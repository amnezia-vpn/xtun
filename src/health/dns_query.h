#ifndef HEALTH_DNS_QUERY_H
#define HEALTH_DNS_QUERY_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace libxtun::health
{
    class DnsQuery
    {
    public:
        DnsQuery() = default;
        DnsQuery(std::uint16_t transactionId, std::uint32_t nonce);

        std::span<const std::byte> bytes() const noexcept
        {
            return m_bytes;
        }

    private:
        std::vector<std::byte> m_bytes;
    };

    class DnsQueryFactory
    {
    public:
        DnsQueryFactory() noexcept;
        DnsQuery next();
    };
}

#endif // HEALTH_DNS_QUERY_H
