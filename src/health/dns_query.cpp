#include "dns_query.h"

#include "net/network_order.h"

#include <cstring>
#include <string_view>

namespace libxtun::health {

namespace {

constexpr std::size_t kDnsHeaderLen = 12;

constexpr std::string_view kProbeDomain = "example.com";
constexpr std::uint16_t kDnsTypeA = 1;
constexpr std::uint16_t kDnsClassIn = 1;
constexpr int kNonceHexDigits = 8;
constexpr std::string_view kHexDigits = "0123456789abcdef";

class DnsFlags {
  public:
    static constexpr std::uint16_t kStandardQuery = 0x0100;

    explicit DnsFlags(std::uint16_t raw) noexcept : m_raw(raw) {}

    bool isResponse() const noexcept { return (m_raw & 0x8000u) != 0; }
    unsigned opcode() const noexcept { return (m_raw >> 11) & 0x0fu; }
    unsigned rcode() const noexcept { return m_raw & 0x0fu; }

  private:
    std::uint16_t m_raw;
};

constexpr unsigned kOpcodeQuery = 0;
constexpr unsigned kRcodeNoError = 0;
constexpr unsigned kRcodeNxDomain = 3;

void appendNonceLabel(std::vector<std::byte> &out, std::uint32_t nonce) {
    out.push_back(static_cast<std::byte>(kNonceHexDigits));
    for (int digit = kNonceHexDigits - 1; digit >= 0; --digit) {
        const auto nibble = (nonce >> (digit * 4)) & 0xfu;
        out.push_back(static_cast<std::byte>(kHexDigits[nibble]));
    }
}

void appendLabels(std::vector<std::byte> &out, std::string_view domain) {
    std::size_t start = 0;
    for (;;) {
        const std::size_t dot = domain.find('.', start);
        const std::string_view label =
            domain.substr(start, dot == std::string_view::npos ? dot : dot - start);
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

DnsQuery::DnsQuery(std::uint16_t transaction_id, std::uint32_t nonce, std::uint16_t source_port)
    : m_transaction_id(transaction_id), m_source_port(source_port) {
    m_bytes.reserve(kDnsHeaderLen + kNonceHexDigits + kProbeDomain.size() + 8);

    net::appendBigEndian16(m_bytes, transaction_id);
    net::appendBigEndian16(m_bytes, DnsFlags::kStandardQuery);
    // QDCOUNT
    net::appendBigEndian16(m_bytes, 1);
    // ANCOUNT
    net::appendBigEndian16(m_bytes, 0);
    // NSCOUNT
    net::appendBigEndian16(m_bytes, 0);
    // ARCOUNT
    net::appendBigEndian16(m_bytes, 0);

    appendNonceLabel(m_bytes, nonce);
    appendLabels(m_bytes, kProbeDomain);
    m_bytes.push_back(std::byte{0});

    net::appendBigEndian16(m_bytes, kDnsTypeA);
    net::appendBigEndian16(m_bytes, kDnsClassIn);
}

bool DnsQuery::matchesResponse(std::span<const std::byte> response) const noexcept {
    if (m_bytes.size() <= kDnsHeaderLen || response.size() < m_bytes.size()) {
        return false;
    }
    if (net::readBigEndian16(response, 0) != m_transaction_id) {
        return false;
    }

    const DnsFlags flags(net::readBigEndian16(response, 2));
    if (!flags.isResponse() || flags.opcode() != kOpcodeQuery) {
        return false;
    }
    if (flags.rcode() != kRcodeNoError && flags.rcode() != kRcodeNxDomain) {
        return false;
    }
    if (net::readBigEndian16(response, 4) != 1) {
        return false;
    }

    const std::size_t question_len = m_bytes.size() - kDnsHeaderLen;
    return std::memcmp(response.data() + kDnsHeaderLen, m_bytes.data() + kDnsHeaderLen,
                       question_len) == 0;
}

DnsQueryFactory::DnsQueryFactory(RandomSource &random) noexcept : m_random(random) {}

DnsQuery DnsQueryFactory::next() {
    const std::uint16_t transaction_id = m_random.next16();
    const std::uint32_t nonce = m_random.next32();
    const auto source_port =
        static_cast<std::uint16_t>(m_random.inRange(kEphemeralPortFirst, kEphemeralPortLast));
    return DnsQuery(transaction_id, nonce, source_port);
}

}
