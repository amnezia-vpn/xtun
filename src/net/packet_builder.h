#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include "net/icmp.h"
#include "net/ip.h"
#include "net/udp.h"
#include "net/view.h"
#include <array>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

namespace libxtun::net
{
    namespace detail
    {
        template<std::size_t O, std::size_t N> inline std::span<std::byte, N> fit(std::span<std::byte> buf)
        {
            static thread_local std::array<std::byte, 64> dummy;
            static_assert(N <= 64);
            return buf.size() >= O + N ? buf.subspan<O, N>() : std::span<std::byte>(dummy).first<N>();
        }
    }

    class PacketBuilder
    {
    public:
        class IpStage;
        class Ip6Stage;
        template<BasicRef L3> class UdpStage;
        template<BasicRef L3, int T> class IcmpStage;

        PacketBuilder(std::span<std::byte> buf) : m_buf(buf)
        {
        }
        [[nodiscard]] IpStage ip(const net::IpAddress &src, const net::IpAddress &dst);
        [[nodiscard]] Ip6Stage ip6(const net::IpAddress &src, const net::IpAddress &dst);
        template<class F> decltype(auto) ipAuto(const IpAddress &src, const IpAddress &dst, F &&f);

    private:
        std::span<std::byte> m_buf;
    };

    class PacketBuilder::IpStage
    {
    public:
        template<std::invocable<IpRef &> F> IpStage &withHeader(F &&func)
        {
            func(m_ref);
            return *this;
        }

        template<int T> [[nodiscard]] IcmpStage<IpRef, T> icmp()
        {
            m_ref.setProtocol(IPPROTO_ICMP);
            return IcmpStage<IpRef, T>(m_ref, m_buf);
        }
        [[nodiscard]] IcmpStage<IpRef, ICMP_ECHO> icmpEchoRequest();
        [[nodiscard]] IcmpStage<IpRef, ICMP_ECHOREPLY> icmpEchoReply();
        [[nodiscard]] UdpStage<IpRef> udp(uint16_t sport, uint16_t dport);

    private:
        friend class PacketBuilder;
        explicit IpStage(std::span<std::byte> buf, const IpAddress &src, const IpAddress &dst)
            : m_ref(detail::fit<0, IpRef::HEADER_LEN>(buf)), m_buf(buf)
        {
            m_ref.setVersion(4)
                    .setIhlBytes(IpRef::HEADER_LEN)
                    .setDscp(0)
                    .setEcn(0)
                    .setTotalLen(IpRef::HEADER_LEN)
                    .setIdentification(0)
                    .setFlags(0)
                    .setFragOffset(0)
                    .setTtl(64)
                    .setProtocol(IPPROTO_RAW)
                    .setSrcAddress(src)
                    .setDstAddress(dst);
        }
        IpRef m_ref;
        std::span<std::byte> m_buf;
    };

    class PacketBuilder::Ip6Stage
    {
    public:
        template<std::invocable<Ip6Ref &> F> Ip6Stage &withHeader(F &&confFunc)
        {
            confFunc(m_ref);
            return *this;
        }

        template<int T> [[nodiscard]] IcmpStage<Ip6Ref, T> icmp()
        {
            m_ref.setNextHeader(IPPROTO_ICMPV6);
            return IcmpStage<Ip6Ref, T>(m_ref, m_buf);
        }
        [[nodiscard]] IcmpStage<Ip6Ref, ICMP6_ECHO_REQUEST> icmpEchoRequest();
        [[nodiscard]] IcmpStage<Ip6Ref, ICMP6_ECHO_REPLY> icmpEchoReply();
        [[nodiscard]] UdpStage<Ip6Ref> udp(uint16_t sport, uint16_t dport);

    private:
        friend class PacketBuilder;
        explicit Ip6Stage(std::span<std::byte> buf, const IpAddress &src, const IpAddress &dst)
            : m_ref(detail::fit<0, Ip6Ref::HEADER_LEN>(buf)), m_buf(buf)
        {
            m_ref.setVersion(6)
                    .setTrafficClass(0)
                    .setFlowLabel(0)
                    .setNextHeader(IPPROTO_RAW)
                    .setHopLimit(64)
                    .setSrcAddress(src)
                    .setDstAddress(dst);
        }
        Ip6Ref m_ref;
        std::span<std::byte> m_buf;
    };

    inline PacketBuilder::IpStage PacketBuilder::ip(const net::IpAddress &src, const net::IpAddress &dst)
    {
        return IpStage { m_buf, src, dst };
    }
    inline PacketBuilder::Ip6Stage PacketBuilder::ip6(const net::IpAddress &src, const net::IpAddress &dst)
    {
        return Ip6Stage { m_buf, src, dst };
    }
    template<class F> decltype(auto) PacketBuilder::ipAuto(const IpAddress &src, const IpAddress &dst, F &&f)
    {
        assert(src.family() == dst.family());
        assert(src.family() == AF_INET || src.family() == AF_INET6);

        if (src.family() == AF_INET6) {
            return std::forward<F>(f)(ip6(src, dst));
        }
        return std::forward<F>(f)(ip(src, dst));
    }

    template<BasicRef L3, int T> class PacketBuilder::IcmpStage
    {
    public:
        template<std::invocable<IcmpRef<T> &> F> IcmpStage &withHeader(F &&func)
        {
            func(m_ref);
            return *this;
        }

        template<typename F>
            requires std::is_invocable_r_v<std::optional<std::size_t>, F, std::span<std::byte>>
        IcmpStage &withPayload(F &&func)
        {
            constexpr auto offset = L3::HEADER_LEN + IcmpRef<T>::HEADER_LEN;
            if (m_buf.size() < offset) {
                return *this;
            }

            std::span<std::byte> payload = m_buf.subspan(offset);
            std::optional<std::size_t> n = std::invoke(std::forward<F>(func), payload);
            if (n && *n > payload.size()) {
                n = std::nullopt;
            }
            m_payloadLen = n;
            return *this;
        }

        [[nodiscard]] std::optional<std::span<std::byte>> finish()
        {
            if (!m_payloadLen) {
                return std::nullopt;
            }
            constexpr auto headerLen = L3::HEADER_LEN + IcmpRef<T>::HEADER_LEN;
            const std::size_t len = headerLen + *m_payloadLen;
            if (m_buf.size() < len) {
                return std::nullopt;
            }
            m_ref.recalcChecksum(m_l3, m_buf.subspan(headerLen, *m_payloadLen));
            if constexpr (std::is_same_v<L3, IpRef>) {
                m_l3.setTotalLen(len).recalcChecksum();
            } else {
                m_l3.setPayloadLength(len - L3::HEADER_LEN);
            }
            return m_buf.first(len);
        }

    private:
        friend class IpStage;
        friend class Ip6Stage;
        IcmpStage(L3 l3, std::span<std::byte> buf)
            : m_l3(l3), m_ref(detail::fit<L3::HEADER_LEN, IcmpRef<T>::HEADER_LEN>(buf)), m_buf(buf)
        {
            m_ref.setType(T).setCode(0);
            if constexpr (requires(IcmpRef<T> r) { r.setIdentifier(0).setSeqNumber(0); }) {
                m_ref.setIdentifier(0).setSeqNumber(0);
            }
        }

        L3 m_l3;
        IcmpRef<T> m_ref;
        std::span<std::byte> m_buf;
        std::optional<std::size_t> m_payloadLen = 0;
    };

    template<BasicRef L3> class PacketBuilder::UdpStage
    {
    public:
        template<std::invocable<UdpRef &> F> UdpStage &withHeader(F &&func)
        {
            func(m_ref);
            return *this;
        }

        template<typename F>
            requires std::is_invocable_r_v<std::optional<std::size_t>, F, std::span<std::byte>>
        UdpStage &withPayload(F &&func)
        {
            constexpr auto offset = L3::HEADER_LEN + UdpRef::HEADER_LEN;
            if (m_buf.size() < offset) {
                return *this;
            }
            std::span<std::byte> payload = m_buf.subspan(offset);
            std::optional<std::size_t> n = std::invoke(std::forward<F>(func), payload);
            if (n && *n > payload.size()) {
                n = std::nullopt;
            }
            m_payloadLen = n;
            return *this;
        }

        [[nodiscard]] std::optional<std::span<std::byte>> finish()
        {
            if (!m_payloadLen) {
                return std::nullopt;
            }
            constexpr auto headerLen = L3::HEADER_LEN + UdpRef::HEADER_LEN;
            const std::size_t len = headerLen + *m_payloadLen;
            if (m_buf.size() < len) {
                return std::nullopt;
            }
            m_ref.setLength(UdpRef::HEADER_LEN + *m_payloadLen).recalcChecksum(m_l3, m_buf.subspan(headerLen, *m_payloadLen));
            if constexpr (std::is_same_v<L3, IpRef>) {
                m_l3.setTotalLen(len).recalcChecksum();
            } else {
                m_l3.setPayloadLength(len - L3::HEADER_LEN);
            }
            return m_buf.first(len);
        }

    private:
        friend class IpStage;
        friend class Ip6Stage;
        UdpStage(L3 l3, std::span<std::byte> buf, uint16_t sport, uint16_t dport)
            : m_l3(l3), m_ref(detail::fit<L3::HEADER_LEN, UdpRef::HEADER_LEN>(buf)), m_buf(buf)
        {
            m_ref.setSport(sport).setDport(dport);
        }

        L3 m_l3;
        UdpRef m_ref;
        std::span<std::byte> m_buf;
        std::optional<std::size_t> m_payloadLen = 0;
    };

    inline PacketBuilder::IcmpStage<IpRef, ICMP_ECHO> PacketBuilder::IpStage::icmpEchoRequest()
    {
        return icmp<ICMP_ECHO>();
    }
    inline PacketBuilder::IcmpStage<IpRef, ICMP_ECHOREPLY> PacketBuilder::IpStage::icmpEchoReply()
    {
        return icmp<ICMP_ECHOREPLY>();
    }
    inline PacketBuilder::UdpStage<IpRef> PacketBuilder::IpStage::udp(uint16_t sport, uint16_t dport)
    {
        m_ref.setProtocol(IPPROTO_UDP);
        return UdpStage<IpRef>(m_ref, m_buf, sport, dport);
    }

    inline PacketBuilder::IcmpStage<Ip6Ref, ICMP6_ECHO_REQUEST> PacketBuilder::Ip6Stage::icmpEchoRequest()
    {
        return icmp<ICMP6_ECHO_REQUEST>();
    }
    inline PacketBuilder::IcmpStage<Ip6Ref, ICMP6_ECHO_REPLY> PacketBuilder::Ip6Stage::icmpEchoReply()
    {
        return icmp<ICMP6_ECHO_REPLY>();
    }
    inline PacketBuilder::UdpStage<Ip6Ref> PacketBuilder::Ip6Stage::udp(uint16_t sport, uint16_t dport)
    {
        m_ref.setNextHeader(IPPROTO_UDP);
        return UdpStage<Ip6Ref>(m_ref, m_buf, sport, dport);
    }
}

#endif
