#include "monitor.h"

#include <algorithm>
#include <utility>

namespace libxtun::health {

namespace {

const char *describe(ConnectionState state) noexcept {
    switch (state) {
        case ConnectionState::Unknown:
            return "health: state cleared";
        case ConnectionState::Connected:
            return "health: connected";
        case ConnectionState::NoNetwork:
            return "health: no network";
        case ConnectionState::Disconnected:
            return "health: disconnected";
    }
    return "health: unnamed state";
}

}

HealthMonitor::HealthMonitor(HealthSettings settings, HealthListener &listener, TrafficMeter &meter,
                             ConnectivityProbe &tunnel_probe, ConnectivityProbe &control_probe,
                             DnsQueryFactory &queries, Scheduler &scheduler, const Clock &clock,
                             LogSink log)
    : m_settings(settings),
      m_listener(listener),
      m_meter(meter),
      m_tunnel_probe(tunnel_probe),
      m_control_probe(control_probe),
      m_queries(queries),
      m_scheduler(scheduler),
      m_clock(clock),
      m_log(std::move(log)),
      m_suspend(clock, kSuspendTolerance),
      m_streak(settings.fail_streak) {}

void HealthMonitor::start() {
    m_scheduler.start([this] { return tick(); },
                      std::chrono::duration_cast<std::chrono::milliseconds>(m_settings.period));
}

void HealthMonitor::stop() noexcept {
    m_scheduler.stop();
}

bool HealthMonitor::running() const noexcept {
    return m_scheduler.running();
}

void HealthMonitor::requestReset() noexcept {
    m_reset_requested.store(true, std::memory_order_release);
}

HealthSnapshot HealthMonitor::snapshot() const {
    std::lock_guard<std::mutex> lock(m_snapshot_mtx);
    return m_snapshot;
}

std::optional<std::chrono::milliseconds> HealthMonitor::tick() {
    const ConnectionState state = evaluate();
    publish(false);

    if (state == ConnectionState::Disconnected) {
        return std::nullopt;
    }

    const auto period = std::chrono::duration_cast<std::chrono::milliseconds>(m_settings.period);
    if (state == ConnectionState::NoNetwork) {
        return period * std::max(1, m_settings.no_network_backoff);
    }
    return period;
}

ConnectionState HealthMonitor::evaluate() {
    const std::uint64_t inbound = m_meter.inboundPackets();
    const bool inbound_fresh = inbound != m_inbound_mark;
    m_inbound_mark = inbound;
    if (inbound_fresh) {
        m_last_inbound_seen = m_clock.steadyNow();
    }

    if (m_reset_requested.exchange(false, std::memory_order_acq_rel) || m_suspend.sample()) {
        m_streak.reset();
        return resetState(ConnectionState::Unknown);
    }

    Observation obs{.inbound_fresh = inbound_fresh};
    if (const auto verdict = resolveVerdict(obs)) {
        m_streak.reset();
        return settle(*verdict);
    }

    if (m_state == ConnectionState::NoNetwork) {
        obs.control = probeWith(m_control_probe);
        if (obs.control != ProbeOutcome::Answered) {
            return m_state;
        }
    }

    obs.tunnel = probeWith(m_tunnel_probe);
    if (const auto verdict = resolveVerdict(obs)) {
        m_streak.reset();
        return settle(*verdict);
    }
    if (obs.tunnel != ProbeOutcome::Failed) {
        return m_state;
    }

    m_streak.increment();
    obs.fail_streak_reached = m_streak.reached();
    if (!obs.fail_streak_reached) {
        return m_state;
    }
    if (obs.control == ProbeOutcome::NotRun) {
        obs.control = probeWith(m_control_probe);
    }

    const auto verdict = resolveVerdict(obs);
    return verdict ? settle(*verdict) : m_state;
}

ProbeOutcome HealthMonitor::probeWith(ConnectivityProbe &probe) {
    publish(true);
    const ProbeOutcome outcome = probe.run(m_queries.next(), m_settings.probe_timeout);
    publish(false);
    return outcome;
}

ConnectionState HealthMonitor::settle(ConnectionState next) noexcept {
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

ConnectionState HealthMonitor::resetState(ConnectionState next) noexcept {
    if (next != m_state && m_log) {
        m_log(describe(next));
    }
    m_state = next;
    return m_state;
}

void HealthMonitor::publish(bool probe_pending) {
    std::lock_guard<std::mutex> lock(m_snapshot_mtx);
    m_snapshot.state = m_state;
    m_snapshot.traffic = m_meter.counters();
    m_snapshot.last_inbound_seen = m_last_inbound_seen;
    m_snapshot.fail_streak = m_streak.count();
    m_snapshot.probe_pending = probe_pending;
}

}
