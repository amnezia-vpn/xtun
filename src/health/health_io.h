#ifndef HEALTH_IO
#define HEALTH_IO

#include "health/health_monitor.h"
#include "health/probe.h"
#include "health/scheduler.h"
#include "net/ip.h"
#include "tunnel_io.h"
#include "util/noncopyable.h"
#include <atomic>
#include <cstddef>
#include <span>
#include <vector>

namespace libxtun::health
{
    class HealthIo final : public TunnelIo, public HealthMonitor, private NonCopyable
    {
    public:
        HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts);
        HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts, Scheduler &scheduler);
        ~HealthIo() override;

        int write(std::span<const std::byte> packet) override;
        int read(std::span<std::byte> buf) override;
        void protectSocket(int fd) override;
        void wake() override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

    private:
        TunnelIo &m_io;
        std::atomic_long m_epoch = 0;
    };
}

#endif
