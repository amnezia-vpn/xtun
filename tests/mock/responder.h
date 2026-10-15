#ifndef TEST_ICMP_RESPONDER
#define TEST_ICMP_RESPONDER

#include "net/icmp.h"
#include "net/ip.h"
#include "net/packet_builder.h"
#include <algorithm>
#include <vector>

namespace libxtun::test
{
    class Responder
    {
    protected:
        template<typename F> static std::vector<std::byte> overIp(std::span<const std::byte> pkt, F &&func)
        {
            if (pkt.empty()) {
                return {};
            }

            switch (static_cast<uint8_t>(pkt[0]) >> 4) {
            case 4: {
                if (pkt.size() < net::IpView::HEADER_LEN) {
                    return {};
                }
                net::IpView ip(pkt.first<net::IpView::HEADER_LEN>());
                std::size_t ihl = ip.ihlBytes(), total = ip.totalLen();
                if (ip.protocol() != IPPROTO_ICMP || pkt.size() < total || ihl > total) {
                    return {};
                };
                return func(ip, pkt.subspan(ihl, total - ihl));
            } break;
            case 6: {
                if (pkt.size() < net::Ip6View::HEADER_LEN) {
                    return {};
                }
                net::Ip6View ip6(pkt.first<net::Ip6View::HEADER_LEN>());
                if (ip6.nextHeader() != IPPROTO_ICMPV6 || pkt.size() < net::Ip6View::HEADER_LEN + ip6.payloadLength()) {
                    return {};
                }
                return func(ip6, pkt.subspan(net::Ip6View::HEADER_LEN, ip6.payloadLength()));
            } break;
            }
            return {};
        }

    public:
        static inline std::vector<std::byte> replyIcmp(std::span<const std::byte> pkt)
        {
            return overIp(pkt, [&](auto &&ip, std::span<const std::byte> rest) -> std::vector<std::byte> {
                constexpr bool v4 = std::is_same_v<std::remove_cvref_t<decltype(ip)>, net::IpView>;
                constexpr int type = v4 ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
                using IcmpView = net::IcmpView<type>;

                if (rest.size() < IcmpView::HEADER_LEN) {
                    return {};
                }
                IcmpView icmp(rest.first<IcmpView::HEADER_LEN>());
                if (icmp.type() != type) {
                    return {};
                }
                auto payload = rest.subspan(IcmpView::HEADER_LEN);

                std::vector<std::byte> buf(pkt.size());
                auto res = net::PacketBuilder(buf).ipAuto(ip.dstAddress(), ip.srcAddress(), [&](auto &&ipStage) {
                    return ipStage.icmpEchoReply()
                            .withHeader([&](auto &&h) {
                                h.setIdentifier(icmp.identifier()).setSeqNumber(icmp.seqNumber());
                            })
                            .withPayload([&](std::span<std::byte> s) -> std::size_t {
                                std::ranges::copy(payload, s.begin());
                                return payload.size();
                            })
                            .finish();
                });
                if (!res) {
                    return {};
                }
                buf.resize(res->size());
                return buf;
            });
        }

        static inline std::vector<std::byte> replyDns(std::span<const std::byte> pkt)
        {
            return {};
        }
    };
}

#endif
