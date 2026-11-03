#ifndef ICMP_PROBE_H
#define ICMP_PROBE_H

#include "health/probe.h"
#include "net/ip.h"
#include "tunnel_io.h"
#include "util/noncopyable.h"
#include <atomic>
#include <memory>

namespace libxtun::health
{
    class IcmpProbe : public TunnelIo, public Probe, private NonCopyable
    {
    public:
        static std::unique_ptr<IcmpProbe> create(TunnelIo &io, net::IpAddress target);
        ~IcmpProbe();

        int read(std::span<std::byte> buf) override;
        void sendProbe() override;

        int write(std::span<const std::byte> packet) override
        {
            return m_io.write(packet);
        }
        libxtun_error protectSocket(int fd) override
        {
            return m_io.protectSocket(fd);
        }
        void wake() override
        {
            m_io.wake();
        }
        void halt() override
        {
            m_io.halt();
        }
        int mtu() const override
        {
            return m_io.mtu();
        }
        std::vector<net::IpPrefix> addresses() override
        {
            return m_io.addresses();
        }

    private:
        IcmpProbe(TunnelIo &io, net::IpAddress src, net::IpAddress dst);

        TunnelIo &m_io;
        std::atomic_bool m_send;
        net::IpAddress m_src;
        net::IpAddress m_dst;
    };
}

#endif
