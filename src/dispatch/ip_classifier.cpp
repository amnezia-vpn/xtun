#include "ip_classifier.h"
#include "io/injection_io.h"
#include "net/ip.h"

namespace libxtun::dispatch
{
    namespace
    {
        std::optional<net::IpAddress> destinationOf(std::span<const std::byte> pkt)
        {
            if (pkt.size() < net::IpView::HEADER_LEN) {
                return {};
            }
            net::IpView view(pkt.first<net::IpView::HEADER_LEN>());
            switch (view.version()) {
            case 4: return view.dstAddress();
            case 6: {
                if (pkt.size() < net::Ip6View::HEADER_LEN) {
                    return {};
                }
                net::Ip6View view6(pkt.first<net::Ip6View::HEADER_LEN>());
                return view6.dstAddress();
            }
            default: return {};
            }
        }
    }

    void IpClassifier::set(InjectionIo *io, const ProxyProfile &profile, std::uint64_t priority)
    {
        Entry entry { .io = io, .priority = priority };
        del(io);

        for (const auto &prefix : profile.routes) {
            m_includeTrie.insert(prefix, entry);
        }
        for (const auto &prefix : profile.excludes) {
            m_excludeTrie.insert(prefix, entry);
        }
    }

    void IpClassifier::del(InjectionIo *io)
    {
        Entry entry { .io = io };
        m_includeTrie.erase(entry);
        m_excludeTrie.erase(entry);
    }

    InjectionIo *IpClassifier::classify(std::span<const std::byte> pkt) const
    {
        auto addr = destinationOf(pkt);
        if (!addr) {
            return nullptr;
        }
        // clang-format off
        return m_includeTrie.match(*addr, [&](Entry included) {
            return nullptr == m_excludeTrie.match(*addr, [&](Entry excluded) { return included == excluded; }).io;
        }).io;
        // clang-format on
    }
}
