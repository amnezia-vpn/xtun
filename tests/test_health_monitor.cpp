#include "health/fake_clock.h"
#include "health/manual_scheduler.h"
#include "health/monitor.h"
#include "util/random.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace
{

    using libxtun::RandomSource;
    using libxtun::health::ConnectionState;
    using libxtun::health::ConnectivityProbe;
    using libxtun::health::DnsQuery;
    using libxtun::health::DnsQueryFactory;
    using libxtun::health::HealthListener;
    using libxtun::health::HealthMonitor;
    using libxtun::health::HealthSettings;
    using libxtun::health::ProbeOutcome;
    using libxtun::health::TrafficMeter;

    class FakeProbe final : public ConnectivityProbe
    {
    public:
        ProbeOutcome outcome = ProbeOutcome::NotRun;
        int runs = 0;
        int aborts = 0;
        std::vector<std::uint16_t> ports;

        ProbeOutcome run(const DnsQuery &query, std::chrono::milliseconds) override
        {
            ++runs;
            ports.push_back(query.sourcePort());
            return outcome;
        }

        void abort() noexcept override
        {
            ++aborts;
        }
    };

    class RecordingListener final : public HealthListener
    {
    public:
        std::vector<ConnectionState> states;

        void onConnectionState(ConnectionState state) noexcept override
        {
            states.push_back(state);
        }
    };

    struct TestSetup
    {
        FakeClock clock;
        RandomSource random { 7 };
        DnsQueryFactory queries { random };
        TrafficMeter meter;
        FakeProbe tunnel;
        FakeProbe control;
        ManualScheduler scheduler;
        RecordingListener listener;
        HealthSettings settings {};
        HealthMonitor monitor { settings, listener, meter, tunnel, control, queries, scheduler, clock };

        void arrive(int packets)
        {
            for (int i = 0; i < packets; ++i) {
                meter.recordInbound(100);
            }
        }
    };

    constexpr auto PERIOD = std::chrono::milliseconds(10000);

} // namespace

TEST(HealthPeriod, ZeroAndNegativeSelectTheDefault)
{
    EXPECT_EQ(HealthSettings::fromSeconds(0).period, libxtun::health::DEFAULT_PERIOD);
    EXPECT_EQ(HealthSettings::fromSeconds(-1).period, libxtun::health::DEFAULT_PERIOD);
    EXPECT_EQ(HealthSettings::fromSeconds(-3600).period, libxtun::health::DEFAULT_PERIOD);
}

TEST(HealthPeriod, SubFloorValuesAreRaisedRatherThanHonoured)
{
    EXPECT_EQ(HealthSettings::fromSeconds(1).period, libxtun::health::PERIOD_FLOOR);
    EXPECT_EQ(HealthSettings::fromSeconds(4).period, libxtun::health::PERIOD_FLOOR);
    EXPECT_EQ(HealthSettings::fromSeconds(5).period, libxtun::health::PERIOD_FLOOR);
}

TEST(HealthPeriod, ConfiguredCadenceAboveTheFloorIsUsedAsGiven)
{
    EXPECT_EQ(HealthSettings::fromSeconds(6).period, std::chrono::seconds(6));
    EXPECT_EQ(HealthSettings::fromSeconds(30).period, std::chrono::seconds(30));
    EXPECT_EQ(HealthSettings::fromSeconds(3600).period, std::chrono::seconds(3600));
}

TEST(HealthPeriod, TheRestOfTheSettingsKeepTheirDefaults)
{
    const HealthSettings settings = HealthSettings::fromSeconds(30);

    EXPECT_EQ(settings.probeTimeout, libxtun::health::PROBE_TIMEOUT);
    EXPECT_EQ(settings.failStreak, libxtun::health::FAIL_STREAK);
    EXPECT_EQ(settings.noNetworkBackoff, libxtun::health::NO_NETWORK_BACKOFF);
    EXPECT_EQ(settings.jitterPercent, libxtun::health::JITTER_PERCENT);
}

TEST(HealthMonitor, StartArmsTheSchedulerWithThePeriod)
{
    TestSetup s;

    s.monitor.start();

    EXPECT_TRUE(s.scheduler.armed());
    EXPECT_EQ(s.scheduler.firstDelay(), PERIOD);
    EXPECT_TRUE(s.monitor.running());
}

TEST(HealthMonitor, NoEvidenceHoldsUnknownAndEmitsNothing)
{
    TestSetup s;
    s.monitor.start();

    EXPECT_EQ(s.scheduler.fire(), PERIOD);

    EXPECT_TRUE(s.listener.states.empty()) << "a verdict was emitted with no evidence for it";
    EXPECT_EQ(s.monitor.snapshot().state, ConnectionState::Unknown);
    EXPECT_EQ(s.tunnel.runs, 1);
    EXPECT_EQ(s.control.runs, 0) << "the control probe ran before the tunnel probe failed";
}

TEST(HealthMonitor, RealTrafficSettlesConnectedWithoutProbing)
{
    TestSetup s;
    s.monitor.start();
    s.arrive(1);

    EXPECT_EQ(s.scheduler.fire(), PERIOD);

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Connected);
    EXPECT_EQ(s.tunnel.runs, 0) << "a busy connection was probed anyway";
}

TEST(HealthMonitor, EmissionIsEdgeTriggered)
{
    TestSetup s;
    s.monitor.start();

    s.arrive(1);
    s.scheduler.fire();
    s.arrive(1);
    s.scheduler.fire();
    s.arrive(1);
    s.scheduler.fire();

    EXPECT_EQ(s.listener.states.size(), 1u) << "the client was told the same state twice";
}

TEST(HealthMonitor, AnsweredTunnelProbeIsConnected)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Answered;
    s.monitor.start();

    s.scheduler.fire();

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Connected);
    EXPECT_EQ(s.control.runs, 0);
}

TEST(HealthMonitor, TheStreakMustBeReachedBeforeTheTunnelIsCalledDead)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Answered;
    s.monitor.start();

    EXPECT_EQ(s.scheduler.fire(), PERIOD);
    EXPECT_TRUE(s.listener.states.empty()) << "one failed probe tore the tunnel down";
    EXPECT_EQ(s.monitor.snapshot().failStreak, 1);

    EXPECT_FALSE(s.scheduler.fire().has_value()) << "a Disconnected verdict must end the loop";

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Disconnected);
    EXPECT_FALSE(s.monitor.running());
}

TEST(HealthMonitor, BothPathsSilentIsNoNetworkAndBacksOff)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();

    s.scheduler.fire();
    const auto next = s.scheduler.fire();

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::NoNetwork);
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, PERIOD * s.settings.noNetworkBackoff);
}

TEST(HealthMonitor, WhileOfflineTheUplinkIsRecheckedBeforeTheTunnel)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();
    s.scheduler.fire();
    s.scheduler.fire();
    ASSERT_EQ(s.monitor.snapshot().state, ConnectionState::NoNetwork);

    const int tunnelRuns = s.tunnel.runs;
    s.scheduler.fire();

    EXPECT_EQ(s.tunnel.runs, tunnelRuns) << "the tunnel was probed while the host was known to be offline";
    EXPECT_EQ(s.control.runs, 2);
}

TEST(HealthMonitor, RecoveringFromNoNetworkTakesTheTunnelProbeAgain)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();
    s.scheduler.fire();
    s.scheduler.fire();
    ASSERT_EQ(s.monitor.snapshot().state, ConnectionState::NoNetwork);

    s.control.outcome = ProbeOutcome::Answered;
    s.tunnel.outcome = ProbeOutcome::Answered;
    s.scheduler.fire();

    ASSERT_EQ(s.listener.states.size(), 2u);
    EXPECT_EQ(s.listener.states[1], ConnectionState::Connected);
}

TEST(HealthMonitor, ResetIsSilentAndClearsTheStreak)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Answered;
    s.monitor.start();
    s.scheduler.fire();
    ASSERT_EQ(s.monitor.snapshot().failStreak, 1);

    s.monitor.requestReset();
    s.scheduler.fire();

    EXPECT_TRUE(s.listener.states.empty()) << "a roam was reported to the client as a state change";
    EXPECT_EQ(s.monitor.snapshot().state, ConnectionState::Unknown);
    EXPECT_EQ(s.monitor.snapshot().failStreak, 0);
}

TEST(HealthMonitor, TrafficFromBeforeARoamCannotSatisfyTheFreshnessRule)
{
    TestSetup s;
    s.monitor.start();
    s.arrive(1);
    s.scheduler.fire();
    ASSERT_EQ(s.listener.states.size(), 1u);

    s.monitor.requestReset();
    s.arrive(1);
    s.scheduler.fire();

    s.scheduler.fire();

    EXPECT_EQ(s.monitor.snapshot().state, ConnectionState::Unknown)
            << "traffic that arrived before the roam was counted after it";
    EXPECT_EQ(s.listener.states.size(), 1u);
}

TEST(HealthMonitor, TheInboundMarkAdvancesOnEveryTickIncludingEarlyReturns)
{
    TestSetup s;
    s.monitor.start();

    s.scheduler.fire();
    s.arrive(1);
    s.scheduler.fire();
    ASSERT_EQ(s.listener.states.size(), 1u);
    ASSERT_EQ(s.listener.states[0], ConnectionState::Connected);

    s.tunnel.outcome = ProbeOutcome::Answered;
    s.scheduler.fire();

    EXPECT_GT(s.tunnel.runs, 1) << "a stale window still counted as fresh traffic";
}

TEST(HealthMonitor, SuspendClearsTheStateWithoutTellingTheClient)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Answered;
    s.monitor.start();
    s.scheduler.fire();
    ASSERT_EQ(s.monitor.snapshot().state, ConnectionState::Connected);

    s.clock.advance(std::chrono::seconds(10));
    s.clock.advanceWallOnly(std::chrono::seconds(60));
    s.scheduler.fire();

    EXPECT_EQ(s.monitor.snapshot().state, ConnectionState::Unknown);
    EXPECT_EQ(s.listener.states.size(), 1u) << "the suspend itself was emitted";
}

TEST(HealthMonitor, UnknownIsNeverEmitted)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Answered;
    s.monitor.start();
    s.scheduler.fire();

    s.monitor.requestReset();
    s.scheduler.fire();
    s.clock.advanceWallOnly(std::chrono::seconds(60));
    s.scheduler.fire();

    EXPECT_TRUE(std::none_of(s.listener.states.begin(), s.listener.states.end(), [](ConnectionState state) {
        return state == ConnectionState::Unknown;
    })) << "Unknown has no libxtun_status to map to and must never reach the client";
}

TEST(HealthMonitor, EveryProbeGetsItsOwnQuery)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();

    s.scheduler.fire();
    s.scheduler.fire();

    ASSERT_GE(s.tunnel.ports.size(), 2u);
    ASSERT_GE(s.control.ports.size(), 1u);
    EXPECT_NE(s.tunnel.ports[0], s.tunnel.ports[1]) << "two probes shared a source port";
    EXPECT_NE(s.tunnel.ports[1], s.control.ports[0]) << "the tunnel and control probes shared one query";
}

TEST(HealthMonitor, TheSnapshotCarriesTheCountersAndTheStreak)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.monitor.start();
    s.arrive(3);
    s.meter.recordOutbound(40);

    s.scheduler.fire();

    const auto snapshot = s.monitor.snapshot();
    EXPECT_EQ(snapshot.state, ConnectionState::Connected);
    EXPECT_EQ(snapshot.traffic.inboundPackets, 3u);
    EXPECT_EQ(snapshot.traffic.inboundBytes, 300u);
    EXPECT_EQ(snapshot.traffic.outboundPackets, 1u);
    EXPECT_EQ(snapshot.failStreak, 0);
    EXPECT_FALSE(snapshot.probePending);
    EXPECT_EQ(snapshot.lastInboundSeen, s.clock.steadyNow());
}

TEST(HealthMonitor, StoppingStopsTheScheduler)
{
    TestSetup s;
    s.monitor.start();

    s.monitor.stop();

    EXPECT_FALSE(s.monitor.running());
    EXPECT_EQ(s.scheduler.stops(), 1);
}

TEST(HealthMonitor, TheMonitorItselfNeitherEmitsToTheAbiNorTearsAnythingDown)
{
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Answered;
    s.monitor.start();
    s.scheduler.fire();
    s.scheduler.fire();

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Disconnected);
    EXPECT_EQ(s.tunnel.aborts, 0) << "the monitor aborted a probe it does not own";
}
