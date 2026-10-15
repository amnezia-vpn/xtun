#include "icmp_probe.h"
#include "net/ip.h"
#include "net/packet_builder.h"
#include "util/overloaded.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>

namespace libxtun::health
{
    std::unique_ptr<IcmpProbe> IcmpProbe::create(TunnelIo &io, net::IpAddress target)
    {
        auto v = io.addresses();
        auto srcPrefix = std::ranges::find_if(
                v, [&](const net::IpPrefix &prefix) { return prefix.address().family() == target.family(); });
        if (srcPrefix == v.end()) {
            return nullptr;
        }
        return std::unique_ptr<IcmpProbe>(new IcmpProbe(io, srcPrefix->address(), target));
    }

    IcmpProbe::IcmpProbe(TunnelIo &io, net::IpAddress src, net::IpAddress dst) : m_io(io), m_src(src), m_dst(dst)
    {
    }

    IcmpProbe::~IcmpProbe()
    {
    }

    int IcmpProbe::read(std::span<std::byte> buf)
    {
        if (m_send.load(std::memory_order_relaxed) && m_send.exchange(false)) [[unlikely]] {
            auto pkt = net::PacketBuilder(buf).ipAuto(m_src, m_dst, [](auto &&ip) {
                return ip
                        .withHeader(overloaded { [](net::IpRef &ref) { ref.setTtl(1); },
                                                 [](net::Ip6Ref &ref) { ref.setHopLimit(1); } })
                        .icmpEchoRequest()
                        .withPayload([](std::span<std::byte> space) -> std::optional<std::size_t> {
                            if (space.size() < 56) {
                                return std::nullopt;
                            }
                            auto payload = space.first<56>();
                            std::ranges::fill(payload, std::byte { 0xFA });
                            return payload.size();
                        })
                        .finish();
            });
            return pkt ? static_cast<int>(pkt->size()) : 0;
        }
        return m_io.read(buf);
    }

    void IcmpProbe::sendProbe()
    {
        m_send = true;
        m_io.wake();
    }
}
