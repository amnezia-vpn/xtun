#ifndef HEALTH_MONITORED_IO_H
#define HEALTH_MONITORED_IO_H

#include "health/probe.h"
#include "health/traffic_meter.h"
#include "tunnel_io.h"
#include "util/noncopyable.h"

#include <atomic>
#include <cstddef>
#include <span>

namespace libxtun::health
{
    class MonitoredIo final : public TunnelIo, private NonCopyable
    {
    public:
        MonitoredIo(TunnelIo &device, TrafficMeter &meter, PacketInterceptor &interceptor) noexcept;

        int read(std::span<std::byte> buf) noexcept override;
        int write(std::span<const std::byte> packet) noexcept override;
        int mtu() const noexcept override
        {
            return m_device.mtu();
        }
        void protectSocket(int fd) noexcept override
        {
            m_device.protectSocket(fd);
        }

        void halt() override
        {
            m_halted.store(true, std::memory_order_release);
            m_device.halt();
        }
        bool halted() const noexcept
        {
            return m_halted.load(std::memory_order_acquire);
        }

        std::vector<net::IpPrefix> addresses() override
        {
            return m_device.addresses();
        }

    private:
        TunnelIo &m_device;
        TrafficMeter &m_meter;
        PacketInterceptor &m_interceptor;
        std::atomic<bool> m_halted { false };
    };
}

#endif // HEALTH_MONITORED_IO_H
