#ifndef HEALTH_IO
#define HEALTH_IO

#include "health/probe.h"
#include "health/scheduler.h"
#include "tunnel_io.h"
#include "util/noncopyable.h"
#include "xtun.h"
#include <atomic>
#include <chrono>

namespace libxtun::health
{
    struct HealthIoOptions
    {
        std::chrono::milliseconds disconnectedPeriod = std::chrono::seconds(1);
        std::chrono::milliseconds connectedPeriod = std::chrono::seconds(15);
    };

    class HealthListener
    {
    public:
        virtual void onStatusChange(libxtun_status status) = 0;
    };

    class HealthIo final : public TunnelIo, private NonCopyable
    {
    public:
        HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts);
        HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts, Scheduler &scheduler);
        ~HealthIo();

        void start();
        void stop();
        int write(std::span<const std::byte> packet) override;

        int read(std::span<std::byte> buf) override
        {
            return m_io.read(buf);
        }
        void protectSocket(int fd) override
        {
            m_io.protectSocket(fd);
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

    protected:
        std::optional<std::chrono::milliseconds> tick();
        void transitionStatus(libxtun_status status);

    private:
        TunnelIo &m_io;
        Probe &m_probe;
        HealthListener &m_listener;
        HealthIoOptions m_opts;
        std::unique_ptr<ThreadedScheduler> m_ownedScheduler;
        Scheduler &m_scheduler;

        std::atomic_long m_epoch = 0;
        std::atomic<libxtun_status> m_status = LIBXTUN_STATUS_DISCONNECTED;
        long m_tickEpoch = 0;
        int m_failCount = 0;
    };
}

#endif
