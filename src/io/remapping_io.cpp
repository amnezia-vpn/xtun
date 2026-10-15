#include "remapping_io.h"
#include "net/checksum.h"
#include "net/ip.h"
#include <cstdint>
#include <memory>

namespace libxtun
{
    std::unique_ptr<RemappingIo> RemappingIo::create(TunnelIo &io, std::span<const net::IpPrefix> prefixes)
    {
        struct Dualstack
        {
            in_addr v4;
            in6_addr v6;
        };
        auto pick = [](std::span<const net::IpPrefix> prefixes) {
            Dualstack ds{};
            for (const auto &prefix : prefixes) {
                const auto &addr = prefix.address();
                const auto bytes = addr.octets();

                switch (addr.family()) {
                case AF_INET: std::memcpy(&ds.v4, bytes.data(), sizeof(ds.v4)); break;
                case AF_INET6: std::memcpy(&ds.v6, bytes.data(), sizeof(ds.v6)); break;
                }
            }
            return ds;
        };

        auto origin = pick(io.addresses());
        auto target = pick(prefixes);

        if (std::memcmp(&target.v4, &origin.v4, sizeof(target.v4)) == 0
            && std::memcmp(&target.v6, &origin.v6, sizeof(target.v6)) == 0) {
            return nullptr;
        }
        return std::unique_ptr<RemappingIo>(new RemappingIo(io, origin.v4, target.v4, origin.v6, target.v6));
    }

    RemappingIo::RemappingIo(TunnelIo &io, in_addr v4origin, in_addr v4target, in6_addr v6origin, in6_addr v6target)
        : m_inner(io), m_v4origin(v4origin), m_v4target(v4target), m_v6origin(v6origin), m_v6target(v6target)
    {
    }

    int RemappingIo::read(std::span<std::byte> buf)
    {
        int n = m_inner.read(buf);
        if (n <= 0) {
            return n;
        }

        auto *pIp = buf.data();
        switch (static_cast<int>(pIp[0] >> 4)) {
        case 4: {
            auto ipLen = (static_cast<unsigned>(pIp[0]) & 0xF) * 4;
            if (n >= 20 && n >= ipLen) {
                auto *pProto = reinterpret_cast<uint8_t *>(pIp + 9);
                auto *pChecksum = reinterpret_cast<uint16_t *>(pIp + 10);
                auto *pSrc = reinterpret_cast<uint32_t *>(pIp + 12);
                if (*pSrc == m_v4origin.s_addr) {
                    uint32_t delta = net::checksumDelta(pSrc, &m_v4target, sizeof(in_addr));
                    *pSrc = m_v4target.s_addr;
                    *pChecksum = net::checksumIncrement(*pChecksum, delta);
                    fixProtoChecksum(pIp + ipLen, n - ipLen, *pProto, delta);
                }
            }
        } break;
        case 6: {
            uint8_t proto;
            int ip6Len = net::ipv6L4Offset(pIp, n, proto);
            if (ip6Len > 0) {
                auto *pSrc = pIp + 8;
                if (std::memcmp(pSrc, &m_v6origin, sizeof(in6_addr)) == 0) {
                    uint32_t delta = net::checksumDelta(pSrc, &m_v6target, sizeof(in6_addr));
                    std::memcpy(pSrc, &m_v6target, sizeof(in6_addr));
                    fixProtoChecksum(pIp + ip6Len, n - ip6Len, proto, delta);
                }
            }
        } break;
        }

        return n;
    }

    int RemappingIo::write(std::span<const std::byte> packet)
    {
        if (packet.empty()) {
            return m_inner.write(packet);
        }

        auto *pIp = const_cast<std::byte *>(packet.data());
        auto n = packet.size();

        switch (static_cast<int>(pIp[0] >> 4)) {
        case 4: {
            auto ipLen = (static_cast<unsigned>(pIp[0]) & 0xF) * 4;
            if (n >= 20 && n >= ipLen) {
                auto *pProto = reinterpret_cast<uint8_t *>(pIp + 9);
                auto *pChecksum = reinterpret_cast<uint16_t *>(pIp + 10);
                auto *pDst = reinterpret_cast<uint32_t *>(pIp + 16);
                if (n >= ipLen && *pDst == m_v4target.s_addr) {
                    uint32_t delta = net::checksumDelta(pDst, &m_v4origin, sizeof(in_addr));
                    *pDst = m_v4origin.s_addr;
                    *pChecksum = net::checksumIncrement(*pChecksum, delta);
                    fixProtoChecksum(pIp + ipLen, n - ipLen, *pProto, delta);
                }
            }
        } break;
        case 6: {
            uint8_t proto;
            int ip6Len = net::ipv6L4Offset(pIp, n, proto);
            if (ip6Len > 0) {
                auto *pDst = pIp + 24;
                if (std::memcmp(pDst, &m_v6target, sizeof(in6_addr)) == 0) {
                    uint32_t delta = net::checksumDelta(pDst, &m_v6origin, sizeof(in6_addr));
                    std::memcpy(pDst, &m_v6origin, sizeof(in6_addr));
                    fixProtoChecksum(pIp + ip6Len, n - ip6Len, proto, delta);
                }
            }
        } break;
        }

        return m_inner.write(packet);
    }

    void RemappingIo::fixProtoChecksum(void *p, int n, uint8_t proto, uint32_t delta)
    {
        auto *b = reinterpret_cast<std::byte *>(p);
        switch (proto) {
        case IPPROTO_ICMPV6:
            if (n >= 8) {
                auto *icmpChecksum = reinterpret_cast<uint16_t *>(b + 2);
                *icmpChecksum = net::checksumIncrement(*icmpChecksum, delta);
            }
            break;
        case IPPROTO_TCP:
            if (n >= 20) {
                auto *tcpChecksum = reinterpret_cast<uint16_t *>(b + 16);
                *tcpChecksum = net::checksumIncrement(*tcpChecksum, delta);
            }
            break;
        case IPPROTO_UDP:
            if (n >= 8) {
                auto *udpChecksum = reinterpret_cast<uint16_t *>(b + 6);
                uint16_t checksum = net::checksumIncrement(*udpChecksum, delta);
                *udpChecksum = (checksum == 0) ? 0xFFFF : checksum;
            }
            break;
        }
    }
}
