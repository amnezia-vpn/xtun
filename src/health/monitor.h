#ifndef HEALTH_MONITOR_H
#define HEALTH_MONITOR_H

#include "health/dns_query.h"
#include "health/probe.h"
#include "health/scheduler.h"
#include "health/state.h"
#include "health/traffic_meter.h"
#include "health/verdict.h"
#include "util/clock.h"
#include "util/noncopyable.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>

namespace libxtun::health {

inline constexpr std::chrono::seconds kDefaultPeriod{10};
inline constexpr std::chrono::seconds kPeriodFloor{5};
inline constexpr std::chrono::milliseconds kProbeTimeout{3000};
inline constexpr std::chrono::seconds kSuspendTolerance{5};
inline constexpr int kFailStreak = 2;
inline constexpr int kNoNetworkBackoff = 4;
inline constexpr int kJitterPercent = 20;

struct HealthSettings {
    std::chrono::seconds period = kDefaultPeriod;
    std::chrono::milliseconds probe_timeout = kProbeTimeout;
    int fail_streak = kFailStreak;
    int no_network_backoff = kNoNetworkBackoff;
    int jitter_percent = kJitterPercent;

    [[nodiscard]] static HealthSettings fromSeconds(int seconds) noexcept;
};

struct HealthSnapshot {
    ConnectionState state = ConnectionState::Unknown;
    TrafficMeter::Counters traffic;
    std::chrono::steady_clock::time_point last_inbound_seen{};
    int fail_streak = 0;
    bool probe_pending = false;
};

class HealthMonitor final : private NonCopyable {
  public:
    HealthMonitor(HealthSettings settings, HealthListener &listener, TrafficMeter &meter,
                  ConnectivityProbe &tunnel_probe, ConnectivityProbe &control_probe,
                  DnsQueryFactory &queries, Scheduler &scheduler, const Clock &clock,
                  LogSink log = {});

    void start();
    void stop() noexcept;
    bool running() const noexcept;

    void requestReset() noexcept;

    HealthSnapshot snapshot() const;

  private:
    std::optional<std::chrono::milliseconds> tick();
    ConnectionState evaluate();
    ProbeOutcome probeWith(ConnectivityProbe &probe);
    ConnectionState settle(ConnectionState next) noexcept;
    ConnectionState resetState(ConnectionState next) noexcept;
    void publish(bool probe_pending);

    HealthSettings m_settings;
    HealthListener &m_listener;
    TrafficMeter &m_meter;
    ConnectivityProbe &m_tunnel_probe;
    ConnectivityProbe &m_control_probe;
    DnsQueryFactory &m_queries;
    Scheduler &m_scheduler;
    const Clock &m_clock;
    LogSink m_log;

    SuspendDetector m_suspend;
    FailureStreak m_streak;
    ConnectionState m_state = ConnectionState::Unknown;

    std::atomic<bool> m_reset_requested{false};
    std::uint64_t m_inbound_mark = 0;
    std::chrono::steady_clock::time_point m_last_inbound_seen{};

    mutable std::mutex m_snapshot_mtx;
    HealthSnapshot m_snapshot;
};

}

#endif // HEALTH_MONITOR_H
