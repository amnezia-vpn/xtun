#ifndef HEALTH_VERDICT_H
#define HEALTH_VERDICT_H

#include "health/probe.h"
#include "health/state.h"
#include "util/clock.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <optional>
#include <ranges>

namespace libxtun::health
{

    struct Observation
    {
        bool inbound_fresh = false;
        ProbeOutcome tunnel = ProbeOutcome::NotRun;
        ProbeOutcome control = ProbeOutcome::NotRun;
        bool fail_streak_reached = false;
    };

    template<typename T> struct Match
    {
        std::optional<T> expected;

        constexpr bool operator()(const T &value) const
        {
            return !expected.has_value() || *expected == value;
        }
    };

    struct VerdictRule
    {
        Match<bool> inbound_fresh;
        Match<ProbeOutcome> tunnel;
        Match<ProbeOutcome> control;
        Match<bool> fail_streak_reached;
        ConnectionState next;
    };

    inline constexpr std::array<VerdictRule, 4> kVerdictRules { {
            { .inbound_fresh = { true }, .next = ConnectionState::Connected },
            { .tunnel = { ProbeOutcome::Answered }, .next = ConnectionState::Connected },
            { .tunnel = { ProbeOutcome::Failed },
              .control = { ProbeOutcome::Answered },
              .fail_streak_reached = { true },
              .next = ConnectionState::Disconnected },
            { .tunnel = { ProbeOutcome::Failed },
              .control = { ProbeOutcome::Failed },
              .fail_streak_reached = { true },
              .next = ConnectionState::NoNetwork },
    } };

    [[nodiscard]] constexpr std::optional<ConnectionState> resolveVerdict(const Observation &obs)
    {
        const auto hit = std::ranges::find_if(kVerdictRules, [&obs](const VerdictRule &rule) {
            return rule.inbound_fresh(obs.inbound_fresh) && rule.tunnel(obs.tunnel) && rule.control(obs.control)
                    && rule.fail_streak_reached(obs.fail_streak_reached);
        });
        return hit == kVerdictRules.end() ? std::nullopt : std::optional { hit->next };
    }

    class FailureStreak
    {
    public:
        explicit FailureStreak(int limit) noexcept : m_limit(limit)
        {
        }

        void increment() noexcept
        {
            ++m_count;
        }
        void reset() noexcept
        {
            m_count = 0;
        }
        bool reached() const noexcept
        {
            return m_count >= m_limit;
        }
        int count() const noexcept
        {
            return m_count;
        }

    private:
        int m_limit;
        int m_count = 0;
    };

    class SuspendDetector
    {
    public:
        SuspendDetector(const Clock &clock, std::chrono::seconds tolerance) noexcept;

        [[nodiscard]] bool sample();

    private:
        const Clock &m_clock;
        std::chrono::seconds m_tolerance;
        std::chrono::steady_clock::time_point m_last_steady;
        std::chrono::system_clock::time_point m_last_wall;
    };

}

#endif // HEALTH_VERDICT_H
