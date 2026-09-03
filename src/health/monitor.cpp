#include "monitor.h"

#include <algorithm>
#include <utility>

namespace libxtun::health
{
    namespace
    {

        const char *describe(ConnectionState state) noexcept
        {
            switch (state) {
            case ConnectionState::Unknown: return "health: state cleared";
            case ConnectionState::Connected: return "health: connected";
            case ConnectionState::NoNetwork: return "health: no network";
            case ConnectionState::Disconnected: return "health: disconnected";
            }
            return "health: unnamed state";
        }

    }

    HealthSettings HealthSettings::fromSeconds(int seconds) noexcept
    {
        HealthSettings settings;
        if (seconds <= 0) {
            return settings;
        }
        const std::chrono::seconds requested { seconds };
        settings.period = requested < PERIOD_FLOOR ? PERIOD_FLOOR : requested;
        return settings;
    }

    HealthMonitor::HealthMonitor(HealthSettings settings, HealthListener &listener, TrafficMeter &meter,
                                 ConnectivityProbe &tunnelProbe, ConnectivityProbe &controlProbe,
                                 DnsQueryFactory &queries, Scheduler &scheduler, const Clock &clock, LogSink log)
        : m_settings(settings),
          m_listener(listener),
          m_meter(meter),
          m_tunnelProbe(tunnelProbe),
          m_controlProbe(controlProbe),
          m_queries(queries),
          m_scheduler(scheduler),
          m_clock(clock),
          m_log(std::move(log)),
          m_suspend(clock, SUSPEND_TOLERANCE),
          m_streak(settings.failStreak)
    {
    }

    void HealthMonitor::start()
    {
        m_scheduler.start([this] { return tick(); },
                          std::chrono::duration_cast<std::chrono::milliseconds>(m_settings.period));
    }

    void HealthMonitor::stop() noexcept
    {
        m_scheduler.stop();
    }

    bool HealthMonitor::running() const noexcept
    {
        return m_scheduler.running();
    }

    void HealthMonitor::requestReset() noexcept
    {
        m_resetRequested.store(true, std::memory_order_release);
    }

    HealthSnapshot HealthMonitor::snapshot() const
    {
        std::lock_guard<std::mutex> lock(m_snapshotMtx);
        return m_snapshot;
    }

    std::optional<std::chrono::milliseconds> HealthMonitor::tick()
    {
        const ConnectionState state = evaluate();
        publish(false);

        if (state == ConnectionState::Disconnected) {
            return std::nullopt;
        }

        const auto period = std::chrono::duration_cast<std::chrono::milliseconds>(m_settings.period);
        if (state == ConnectionState::NoNetwork) {
            return period * std::max(1, m_settings.noNetworkBackoff);
        }
        return period;
    }

    ConnectionState HealthMonitor::evaluate()
    {
        const std::uint64_t inbound = m_meter.inboundPackets();
        const bool inboundFresh = inbound != m_inboundMark;
        m_inboundMark = inbound;
        if (inboundFresh) {
            m_lastInboundSeen = m_clock.steadyNow();
        }

        if (m_resetRequested.exchange(false, std::memory_order_acq_rel) || m_suspend.sample()) {
            m_streak.reset();
            return resetState(ConnectionState::Unknown);
        }

        Observation obs { .inboundFresh = inboundFresh };
        if (const auto verdict = resolveVerdict(obs)) {
            m_streak.reset();
            return settle(*verdict);
        }

        if (m_state == ConnectionState::NoNetwork) {
            obs.control = probeWith(m_controlProbe);
            if (obs.control != ProbeOutcome::Answered) {
                return m_state;
            }
        }

        obs.tunnel = probeWith(m_tunnelProbe);
        if (const auto verdict = resolveVerdict(obs)) {
            m_streak.reset();
            return settle(*verdict);
        }
        if (obs.tunnel != ProbeOutcome::Failed) {
            return m_state;
        }

        m_streak.increment();
        obs.failStreakReached = m_streak.reached();
        if (!obs.failStreakReached) {
            return m_state;
        }
        if (obs.control == ProbeOutcome::NotRun) {
            obs.control = probeWith(m_controlProbe);
        }

        const auto verdict = resolveVerdict(obs);
        return verdict ? settle(*verdict) : m_state;
    }

    ProbeOutcome HealthMonitor::probeWith(ConnectivityProbe &probe)
    {
        publish(true);
        const ProbeOutcome outcome = probe.run(m_queries.next(), m_settings.probeTimeout);
        publish(false);
        return outcome;
    }

    ConnectionState HealthMonitor::settle(ConnectionState next) noexcept
    {
        if (next == m_state) {
            return m_state;
        }
        m_state = next;
        if (m_log) {
            m_log(describe(next));
        }
        m_listener.onConnectionState(next);
        return m_state;
    }

    ConnectionState HealthMonitor::resetState(ConnectionState next) noexcept
    {
        if (next != m_state && m_log) {
            m_log(describe(next));
        }
        m_state = next;
        return m_state;
    }

    void HealthMonitor::publish(bool probePending)
    {
        std::lock_guard<std::mutex> lock(m_snapshotMtx);
        m_snapshot.state = m_state;
        m_snapshot.traffic = m_meter.counters();
        m_snapshot.lastInboundSeen = m_lastInboundSeen;
        m_snapshot.failStreak = m_streak.count();
        m_snapshot.probePending = probePending;
    }

}
