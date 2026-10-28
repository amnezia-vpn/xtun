#ifndef TEST_ICMP_RESPONDER
#define TEST_ICMP_RESPONDER

#include "net/dns.h"
#include "net/icmp.h"
#include "net/ip.h"
#include "net/packet_builder.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "util/random.h"
#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace libxtun::test
{
    class Responder
    {
    protected:
        template<uint8_t PROTO4, uint8_t PROTO6 = PROTO4, typename F>
        static std::vector<std::byte> overIp(std::span<const std::byte> pkt, F &&func)
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
                if (ip.protocol() != PROTO4 || pkt.size() < total || ihl > total) {
                    return {};
                };
                return func(ip, pkt.subspan(ihl, total - ihl));
            } break;
            case 6: {
                if (pkt.size() < net::Ip6View::HEADER_LEN) {
                    return {};
                }
                net::Ip6View ip6(pkt.first<net::Ip6View::HEADER_LEN>());
                if (ip6.nextHeader() != PROTO6 || pkt.size() < net::Ip6View::HEADER_LEN + ip6.payloadLength()) {
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
            return overIp<IPPROTO_ICMP, IPPROTO_ICMPV6>(
                    pkt, [&](auto &&ip, std::span<const std::byte> rest) -> std::vector<std::byte> {
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

        static inline std::vector<std::byte> replyTcpSyn(std::span<const std::byte> pkt)
        {
            return overIp<IPPROTO_TCP>(pkt, [&](auto &&ipIn, std::span<const std::byte> rest) -> std::vector<std::byte> {
                if (rest.size() < net::TcpView::HEADER_LEN) {
                    return {};
                }
                net::TcpView tcpIn(rest.first<net::TcpView::HEADER_LEN>());
                if ((tcpIn.flags() & net::TcpFlag::SYN) == 0) {
                    return {};
                }

                std::vector<std::byte> buf(pkt.size());
                auto res = net::PacketBuilder(buf).ipAuto(ipIn.dstAddress(), ipIn.srcAddress(), [&](auto &&ipOut) {
                    return ipOut.tcp(tcpIn.dport(), tcpIn.sport())
                            .withHeader([&](net::TcpRef &h) {
                                h.setSeqNumber(rand::next32())
                                        .setAckNumber(tcpIn.seqNumber() + 1)
                                        .setFlags(net::TcpFlag::SYN | net::TcpFlag::ACK)
                                        .setWindow(65535);
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
            return overIp<IPPROTO_UDP>(pkt, [&](auto &&ipIn, std::span<const std::byte> rest) -> std::vector<std::byte> {
                constexpr std::uint16_t dnsPort = 53;
                constexpr std::uint32_t ttlSeconds = 60;

                if (rest.size() < net::UdpView::HEADER_LEN) {
                    return {};
                }
                net::UdpView udpIn(rest.first<net::UdpView::HEADER_LEN>());
                if (udpIn.dport() != dnsPort || udpIn.length() < net::UdpView::HEADER_LEN
                    || udpIn.length() > rest.size()) {
                    return {};
                }
                const auto query = rest.subspan(net::UdpView::HEADER_LEN, udpIn.length() - net::UdpView::HEADER_LEN);
                if (query.size() < net::DnsView::HEADER_LEN) {
                    return {};
                }
                net::DnsView dnsIn(query.first<net::DnsView::HEADER_LEN>());
                const auto question = net::DnsQuestion::parse(query);
                if ((dnsIn.flags() & net::DnsFlag::RESPONSE) != 0 || dnsIn.questions() != 1 || !question
                    || question->type != net::DnsType::A) {
                    return {};
                }

                const net::IpAddress resolver = ipIn.dstAddress();
                const bool answered = resolver.family() == AF_INET;

                std::vector<std::byte> dns(query.begin(), query.begin() + question->end);
                const std::span<std::byte> dnsBytes(dns);
                net::DnsRef dnsOut(dnsBytes.first<net::DnsRef::HEADER_LEN>());
                dnsOut.setFlags(net::DnsFlag::RESPONSE | net::DnsFlag::RECURSION_DESIRED
                                | net::DnsFlag::RECURSION_AVAILABLE)
                        .setAnswers(answered ? 1 : 0)
                        .setAuthorities(0)
                        .setAdditionals(0);
                if (answered) {
                    net::DnsARecord { ttlSeconds, resolver }.appendTo(dns);
                }

                std::vector<std::byte> buf(net::Ip6View::HEADER_LEN + net::UdpView::HEADER_LEN + dns.size());
                auto res = net::PacketBuilder(buf).ipAuto(resolver, ipIn.srcAddress(), [&](auto &&ipOut) {
                    return ipOut.udp(udpIn.dport(), udpIn.sport())
                            .withPayload([&](std::span<std::byte> payload) -> std::optional<std::size_t> {
                                if (payload.size() < dns.size()) {
                                    return std::nullopt;
                                }
                                std::ranges::copy(dns, payload.begin());
                                return dns.size();
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
    };
}

#endif
