#include "health_io.h"
#include "health/probe.h"
#include "health/scheduler.h"
#include "xtun.h"
#include <memory>

namespace libxtun::health
{
    HealthIo::HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts)
        : m_io(io),
          m_probe(probe),
          m_listener(listener),
          m_opts(std::move(opts)),
          m_ownedScheduler(std::make_unique<ThreadedScheduler>()),
          m_scheduler(*m_ownedScheduler)
    {
    }

    HealthIo::HealthIo(TunnelIo &io, Probe &probe, HealthListener &listener, HealthIoOptions opts, Scheduler &scheduler)
        : m_io(io),
          m_probe(probe),
          m_listener(listener),
          m_opts(std::move(opts)),
          m_ownedScheduler(nullptr),
          m_scheduler(scheduler)
    {
    }

    HealthIo::~HealthIo()
    {
        stop();
    }

    void HealthIo::start()
    {
        m_scheduler.start([this] { return tick(); }, std::chrono::milliseconds(0));
    }

    void HealthIo::stop()
    {
        m_scheduler.stop();
        transitionStatus(LIBXTUN_STATUS_DISCONNECTED);
    }

    std::optional<std::chrono::milliseconds> HealthIo::tick()
    {
        using namespace std::chrono;

        if (long epoch = m_epoch.load(); epoch != m_tickEpoch) {
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

    void HealthIo::transitionStatus(libxtun_status status)
    {
        if (m_status != status) {
            m_status = status;
            m_listener.onStatusChange(status);
        }
    }

    int HealthIo::write(std::span<const std::byte> packet)
    {
        int n = m_io.write(packet);
        if (n > 0) {
            m_epoch++;
            if (m_status.load() != LIBXTUN_STATUS_CONNECTED) {
                m_scheduler.wake();
            }
        }
        return n;
    }
}
