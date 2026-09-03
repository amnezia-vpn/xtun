#ifndef HEALTH_DNS_QUERY_H
#define HEALTH_DNS_QUERY_H

#include "util/random.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace libxtun::health
{

    inline constexpr std::uint16_t DNS_PORT = 53;
    inline constexpr std::uint16_t EPHEMERAL_PORT_FIRST = 49152;
    inline constexpr std::uint16_t EPHEMERAL_PORT_LAST = 65535;
    inline constexpr std::size_t MAX_DNS_RESPONSE = 512;

    class DnsQuery
    {
    public:
        DnsQuery() = default;
        DnsQuery(std::uint16_t transactionId, std::uint32_t nonce, std::uint16_t sourcePort);

        std::span<const std::byte> bytes() const noexcept
        {
            return m_bytes;
        }
        std::uint16_t sourcePort() const noexcept
        {
            return m_sourcePort;
        }

        bool matchesResponse(std::span<const std::byte> response) const noexcept;

    private:
        std::vector<std::byte> m_bytes;
        std::uint16_t m_transactionId = 0;
        std::uint16_t m_sourcePort = 0;
    };

    class DnsQueryFactory
    {
    public:
        explicit DnsQueryFactory(RandomSource &random) noexcept;

        DnsQuery next();

    private:
        RandomSource &m_random;
    };

}

#endif // HEALTH_DNS_QUERY_H
