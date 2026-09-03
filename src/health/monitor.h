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

namespace libxtun::health
{

    inline constexpr std::chrono::seconds DEFAULT_PERIOD { 10 };
    inline constexpr std::chrono::seconds PERIOD_FLOOR { 5 };
    inline constexpr std::chrono::milliseconds PROBE_TIMEOUT { 3000 };
    inline constexpr std::chrono::seconds SUSPEND_TOLERANCE { 5 };
    inline constexpr int FAIL_STREAK = 2;
    inline constexpr int NO_NETWORK_BACKOFF = 4;
    inline constexpr int JITTER_PERCENT = 20;

    struct HealthSettings
    {
        std::chrono::seconds period = DEFAULT_PERIOD;
        std::chrono::milliseconds probeTimeout = PROBE_TIMEOUT;
        int failStreak = FAIL_STREAK;
        int noNetworkBackoff = NO_NETWORK_BACKOFF;
        int jitterPercent = JITTER_PERCENT;

        [[nodiscard]] static HealthSettings fromSeconds(int seconds) noexcept;
    };

    struct HealthSnapshot
    {
        ConnectionState state = ConnectionState::Unknown;
        TrafficMeter::Counters traffic;
        std::chrono::steady_clock::time_point lastInboundSeen {};
        int failStreak = 0;
        bool probePending = false;
    };

    class HealthMonitor final : private NonCopyable
    {
    public:
        HealthMonitor(HealthSettings settings, HealthListener &listener, TrafficMeter &meter,
                      ConnectivityProbe &tunnelProbe, ConnectivityProbe &controlProbe, DnsQueryFactory &queries,
                      Scheduler &scheduler, const Clock &clock, LogSink log = {});

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
        void publish(bool probePending);

        HealthSettings m_settings;
        HealthListener &m_listener;
        TrafficMeter &m_meter;
        ConnectivityProbe &m_tunnelProbe;
        ConnectivityProbe &m_controlProbe;
        DnsQueryFactory &m_queries;
        Scheduler &m_scheduler;
        const Clock &m_clock;
        LogSink m_log;

        SuspendDetector m_suspend;
        FailureStreak m_streak;
        ConnectionState m_state = ConnectionState::Unknown;

        std::atomic<bool> m_resetRequested { false };
        std::uint64_t m_inboundMark = 0;
        std::chrono::steady_clock::time_point m_lastInboundSeen {};

        mutable std::mutex m_snapshotMtx;
        HealthSnapshot m_snapshot;
    };

}

#endif // HEALTH_MONITOR_H
