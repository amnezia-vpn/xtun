#include "health_monitor.h"
#include "health/probe.h"
#include "health/scheduler.h"
#include "xtun.h"
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>

namespace libxtun::health
{
    HealthMonitor::HealthMonitor(Activity activity, Probe &probe, HealthListener &listener, HealthIoOptions opts)
        : m_activity(activity),
          m_probe(probe),
          m_listener(listener),
          m_opts(opts),
          m_ownedScheduler(std::make_unique<ThreadedScheduler>()),
          m_scheduler(*m_ownedScheduler)
    {
    }

    HealthMonitor::HealthMonitor(Activity activity, Probe &probe, HealthListener &listener, HealthIoOptions opts,
                                 Scheduler &scheduler)
        : m_activity(activity),
          m_probe(probe),
          m_listener(listener),
          m_opts(opts),
          m_ownedScheduler(nullptr),
          m_scheduler(scheduler)
    {
    }

    HealthMonitor::~HealthMonitor()
    {
        stop();
    }

    void HealthMonitor::start()
    {
        m_scheduler.start([this] { return tick(); }, std::chrono::milliseconds(0));
    }

    void HealthMonitor::stop()
    {
        m_scheduler.stop();
        transitionStatus(LIBXTUN_STATUS_DISCONNECTED);
    }

    void HealthMonitor::wake()
    {
        m_scheduler.wake();
    }

    libxtun_status HealthMonitor::status()
    {
        return m_status.load();
    }

    std::optional<std::chrono::milliseconds> HealthMonitor::tick()
    {
        using namespace std::chrono;

        if (std::uint64_t epoch = m_activity(); epoch != m_tickEpoch) {
            transitionStatus(LIBXTUN_STATUS_CONNECTED);
            m_tickEpoch = epoch;
            m_failCount = 0;
            return m_opts.connectedPeriod;
        } else {
            m_probe.sendProbe();
            if (m_failCount == 5) {
                transitionStatus(LIBXTUN_STATUS_DISCONNECTED);
            } else {
                m_failCount++;
            }
            return m_opts.disconnectedPeriod;
        }
    }

    void HealthMonitor::transitionStatus(libxtun_status status)
    {
        if (m_status != status) {
            m_status = status;
            m_listener.onStatusChange(status);
        }
    }
}
