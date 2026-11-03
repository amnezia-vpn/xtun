#ifndef REMAPPING_IO_H
#define REMAPPING_IO_H

#include "net/ip.h"
#include "net/sys.h" // IWYU pragma: keep
#include "tunnel_io.h"
#include "util/noncopyable.h"
#include <cstring>
#include <memory>

namespace libxtun
{
    class RemappingIo final : public TunnelIo, private NonCopyable
    {
    public:
        static std::unique_ptr<RemappingIo> create(TunnelIo &io, std::span<const net::IpPrefix> prefixes);

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;

        libxtun_error protectSocket(int fd) override
        {
            return m_inner.protectSocket(fd);
        }
        void wake() override
        {
            m_inner.wake();
        }
        void halt() override
        {
            m_inner.halt();
        }
        int mtu() const override
        {
            return m_inner.mtu();
        }
        std::vector<net::IpPrefix> addresses() override
        {
            return m_inner.addresses();
        }

    private:
        RemappingIo(TunnelIo &io, in_addr v4origin, in_addr v4target, in6_addr v6origin, in6_addr v6target);

        void fixProtoChecksum(void *p, int n, uint8_t proto, uint32_t delta);

        TunnelIo &m_inner;
        in_addr m_v4origin {};
        in_addr m_v4target {};
        in6_addr m_v6origin {};
        in6_addr m_v6target {};
    };
}

#endif
