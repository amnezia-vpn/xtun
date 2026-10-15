#include "dns_probe.h"
#include "net/ip.h"
#include "net/packet_builder.h"
#include "util/random.h"
#include <algorithm>
#include <cstring>
#include <memory>

namespace
{
    inline constexpr std::uint16_t DNS_PORT = 53;
    inline constexpr std::uint16_t EPHEMERAL_PORT_FIRST = 49152;
    inline constexpr std::uint16_t EPHEMERAL_PORT_LAST = 65535;
}

namespace libxtun::health
{
    std::unique_ptr<DnsProbe> DnsProbe::create(TunnelIo &io, net::IpAddress dns)
    {
        auto v = io.addresses();
        auto found = std::find_if(v.begin(), v.end(), [&](const net::IpPrefix &prefix) {
            return prefix.address().family() == dns.family();
        });
        if (found == v.end()) {
            return nullptr;
        }
        return std::unique_ptr<DnsProbe>(new DnsProbe(io, found->address(), dns));
    }

    DnsProbe::DnsProbe(TunnelIo &io, net::IpAddress src, net::IpAddress dst) : m_io(io), m_src(src), m_dst(dst)
    {
    }

    DnsProbe::~DnsProbe()
    {
    }

    void DnsProbe::sendProbe()
    {
        m_send = true;
        m_io.wake();
    }

    int DnsProbe::read(std::span<std::byte> buf)
    {
        if (m_send.load(std::memory_order_relaxed) && m_send.exchange(false)) [[unlikely]] {
            auto sport = rand::next16(EPHEMERAL_PORT_FIRST, EPHEMERAL_PORT_LAST);
            auto pkt = net::PacketBuilder(buf).ipAuto(m_src, m_dst, [&](auto &&ip) {
                return ip.udp(sport, DNS_PORT)
                        .withPayload([&](std::span<std::byte> payload) -> std::optional<std::size_t> {
                            // TODO: make queryFactory to utilize the existing buffer
                            auto query = m_queryFactory.next();
                            auto bytes = query.bytes();
                            if (payload.size() < bytes.size()) {
                                return std::nullopt;
                            }
                            std::ranges::copy(bytes, payload.begin());
                            return bytes.size();
                        })
                        .finish();
            });
            return pkt ? static_cast<int>(pkt->size()) : 0;
        }
        return m_io.read(buf);
    }
}
