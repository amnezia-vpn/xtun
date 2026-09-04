#include "health/fake_clock.h"
#include "health/verdict.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <optional>

namespace
{

    using libxtun::health::ConnectionState;
    using libxtun::health::FailureStreak;
    using libxtun::health::Observation;
    using libxtun::health::ProbeOutcome;
    using libxtun::health::resolveVerdict;
    using libxtun::health::SuspendDetector;

    constexpr std::array<ProbeOutcome, 3> OUTCOMES { ProbeOutcome::NotRun, ProbeOutcome::Answered, ProbeOutcome::Failed };

} // namespace

TEST(HealthVerdict, FreshInboundTrafficAloneSettlesConnected)
{
    for (ProbeOutcome tunnel : OUTCOMES) {
        for (ProbeOutcome control : OUTCOMES) {
            for (bool streak : { false, true }) {
                const Observation obs {
                    .inboundFresh = true, .tunnel = tunnel, .control = control, .failStreakReached = streak
                };
                EXPECT_EQ(resolveVerdict(obs), ConnectionState::Connected)
                        << "fresh inbound traffic did not settle the verdict on its own";
            }
        }
    }
}

TEST(HealthVerdict, AnsweredTunnelProbeIsConnectedRegardlessOfTheRest)
{
    for (ProbeOutcome control : OUTCOMES) {
        for (bool streak : { false, true }) {
            const Observation obs { .tunnel = ProbeOutcome::Answered, .control = control, .failStreakReached = streak };
            EXPECT_EQ(resolveVerdict(obs), ConnectionState::Connected);
        }
    }
}

TEST(HealthVerdict, OnlineHostWithADeadTunnelIsDisconnected)
{
    const Observation obs { .tunnel = ProbeOutcome::Failed, .control = ProbeOutcome::Answered, .failStreakReached = true };

    EXPECT_EQ(resolveVerdict(obs), ConnectionState::Disconnected);
}

TEST(HealthVerdict, NoConnectivityAtAllIsNoNetwork)
{
    const Observation obs { .tunnel = ProbeOutcome::Failed, .control = ProbeOutcome::Failed, .failStreakReached = true };

    EXPECT_EQ(resolveVerdict(obs), ConnectionState::NoNetwork);
}

TEST(HealthVerdict, TheStreakGatesEveryTeardownVerdict)
{
    for (ProbeOutcome control : OUTCOMES) {
        const Observation obs { .tunnel = ProbeOutcome::Failed, .control = control, .failStreakReached = false };
        EXPECT_FALSE(resolveVerdict(obs).has_value())
                << "a single failed probe produced a verdict before the streak was reached";
    }
}

TEST(HealthVerdict, NoEvidenceYieldsNoVerdict)
{
    EXPECT_FALSE(resolveVerdict(Observation {}).has_value());

    const Observation noTarget { .tunnel = ProbeOutcome::NotRun,
                                 .control = ProbeOutcome::NotRun,
                                 .failStreakReached = true };
    EXPECT_FALSE(resolveVerdict(noTarget).has_value()) << "a probe that could not run must never decide anything";

    const Observation unbindableControl { .tunnel = ProbeOutcome::Failed,
                                          .control = ProbeOutcome::NotRun,
                                          .failStreakReached = true };
    EXPECT_FALSE(resolveVerdict(unbindableControl).has_value())
            << "a failed tunnel probe with no control evidence must hold, not tear down";
}

TEST(HealthVerdict, EveryConclusiveVerdictNeedsEitherTrafficOrAProbeResult)
{
    for (bool fresh : { false, true }) {
        for (ProbeOutcome tunnel : OUTCOMES) {
            for (ProbeOutcome control : OUTCOMES) {
                for (bool streak : { false, true }) {
                    const Observation obs {
                        .inboundFresh = fresh, .tunnel = tunnel, .control = control, .failStreakReached = streak
                    };
                    const auto verdict = resolveVerdict(obs);
                    if (!verdict.has_value()) {
                        continue;
                    }
                    EXPECT_NE(*verdict, ConnectionState::Unknown)
                            << "the table produced Unknown, which has no ABI value";
                    const bool justified = fresh || tunnel == ProbeOutcome::Answered
                            || (tunnel == ProbeOutcome::Failed && streak && control != ProbeOutcome::NotRun);
                    EXPECT_TRUE(justified) << "a verdict was reached without evidence for it";
                }
            }
        }
    }
}

TEST(HealthStreak, ReachesTheLimitExactlyAndNotBefore)
{
    FailureStreak streak(2);

    EXPECT_FALSE(streak.reached());
    EXPECT_EQ(streak.count(), 0);

    streak.increment();
    EXPECT_FALSE(streak.reached()) << "one failure tripped a two-failure threshold";
    EXPECT_EQ(streak.count(), 1);

    streak.increment();
    EXPECT_TRUE(streak.reached());
    EXPECT_EQ(streak.count(), 2);

    streak.increment();
    EXPECT_TRUE(streak.reached());
}

TEST(HealthStreak, ResetPreventsAccumulationAcrossGoodPeriods)
{
    FailureStreak streak(2);

    streak.increment();
    streak.reset();
    streak.increment();

    EXPECT_FALSE(streak.reached()) << "an intermittent failure accumulated across a conclusive verdict";
    EXPECT_EQ(streak.count(), 1);
}

TEST(HealthStreak, LimitOfOneTripsOnTheFirstFailure)
{
    FailureStreak streak(1);

    EXPECT_FALSE(streak.reached());
    streak.increment();
    EXPECT_TRUE(streak.reached());
}

TEST(HealthSuspend, AgreeingClocksAreNotASuspend)
{
    FakeClock clock;
    SuspendDetector detector(clock, std::chrono::seconds(5));

    clock.advance(std::chrono::seconds(10));
    EXPECT_FALSE(detector.sample());

    clock.advance(std::chrono::seconds(10));
    EXPECT_FALSE(detector.sample());
}

TEST(HealthSuspend, WallTimeRunningAheadOfSteadyTimeIsASuspend)
{
    FakeClock clock;
    SuspendDetector detector(clock, std::chrono::seconds(5));

    clock.advance(std::chrono::seconds(10));
    clock.advanceWallOnly(std::chrono::seconds(30));

    EXPECT_TRUE(detector.sample()) << "the process slept without the detector noticing";
}

TEST(HealthSuspend, DivergenceWithinToleranceIsIgnored)
{
    FakeClock clock;
    SuspendDetector detector(clock, std::chrono::seconds(5));

    clock.advance(std::chrono::seconds(10));
    clock.advanceWallOnly(std::chrono::seconds(2));

    EXPECT_FALSE(detector.sample()) << "ordinary clock skew was reported as a suspend";
}

TEST(HealthSuspend, BackwardsWallClockJumpIsAlsoDetected)
{
    FakeClock clock;
    SuspendDetector detector(clock, std::chrono::seconds(5));

    clock.advance(std::chrono::seconds(10));
    clock.advanceSteadyOnly(std::chrono::seconds(30));

    EXPECT_TRUE(detector.sample());
}

TEST(HealthSuspend, EachSampleMeasuresOnlySinceTheLastOne)
{
    FakeClock clock;
    SuspendDetector detector(clock, std::chrono::seconds(5));

    clock.advance(std::chrono::seconds(10));
    clock.advanceWallOnly(std::chrono::seconds(30));
    ASSERT_TRUE(detector.sample());

    clock.advance(std::chrono::seconds(10));
    EXPECT_FALSE(detector.sample()) << "the detector kept reporting a suspend it already reported";
}
