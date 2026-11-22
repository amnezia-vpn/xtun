#ifndef HEALTH_HEALTH_MONITOR_H
#define HEALTH_HEALTH_MONITOR_H

#include "health/probe.h"
#include "health/scheduler.h"
#include "xtun.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

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

    protected:
        ~HealthListener() = default;
    };

    class HealthMonitor
    {
    public:
        using Activity = std::function<std::uint64_t(void)>;

        HealthMonitor(Activity activity, Probe &probe, HealthListener &listener, HealthIoOptions opts);
        HealthMonitor(Activity activity, Probe &probe, HealthListener &listener, HealthIoOptions opts,
                      Scheduler &scheduler);
        virtual ~HealthMonitor();

        void start();
        void stop();
        void wake();
        libxtun_status status();

    protected:
        std::optional<std::chrono::milliseconds> tick();
        void transitionStatus(libxtun_status status);

    private:
        Activity m_activity;
        Probe &m_probe;
        HealthListener &m_listener;
        HealthIoOptions m_opts;
        std::unique_ptr<ThreadedScheduler> m_ownedScheduler;
        Scheduler &m_scheduler;

        std::atomic<libxtun_status> m_status = LIBXTUN_STATUS_DISCONNECTED;
        std::uint64_t m_tickEpoch = 0;
        int m_failCount = 0;
    };
}

#endif // HEALTH_HEALTH_MONITOR_H
