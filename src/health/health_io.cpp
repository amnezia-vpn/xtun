#include "health_io.h"
#include "health/health_monitor.h"
#include "health/probe.h"
#include "health/scheduler.h"
#include "net/ip.h"
#include "tunnel_io.h"
#include "xtun.h"
#include <cstddef>
#include <span>
#include <vector>

namespace libxtun::health
{
    HealthIo::HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts)
        : HealthMonitor([this]() { return m_epoch.load(); }, probe, listener, opts), m_io(io)
    {
    }

    HealthIo::HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts, Scheduler &scheduler)
        : HealthMonitor([this]() { return m_epoch.load(); }, probe, listener, opts, scheduler), m_io(io)
    {
    }

    HealthIo::~HealthIo()
    {
        stop();
    }

    int HealthIo::write(std::span<const std::byte> packet)
    {
        int n = m_io.write(packet);
        if (n > 0) {
            m_epoch++;
            if (HealthMonitor::status() != LIBXTUN_STATUS_CONNECTED) {
                HealthMonitor::wake();
            }
        }
        return n;
    }

    int HealthIo::read(std::span<std::byte> buf)
    {
        return m_io.read(buf);
    }

    void HealthIo::protectSocket(int fd)
    {
        m_io.protectSocket(fd);
    }

    void HealthIo::wake()
    {
        m_io.wake();
    }

    void HealthIo::halt()
    {
        m_io.halt();
    }

    int HealthIo::mtu() const
    {
        return m_io.mtu();
    }

    std::vector<net::IpPrefix> HealthIo::addresses()
    {
        return m_io.addresses();
    }
}
