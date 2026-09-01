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

namespace {

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

class FakeProbe final : public ConnectivityProbe {
  public:
    ProbeOutcome outcome = ProbeOutcome::NotRun;
    int runs = 0;
    int aborts = 0;
    std::vector<std::uint16_t> ports;
    std::function<void()> while_running;

    ProbeOutcome run(const DnsQuery &query, std::chrono::milliseconds) override {
        ++runs;
        ports.push_back(query.sourcePort());
        if (while_running) {
            while_running();
        }
        return outcome;
    }

    void abort() noexcept override { ++aborts; }
};

class RecordingListener final : public HealthListener {
  public:
    std::vector<ConnectionState> states;

    void onConnectionState(ConnectionState state) noexcept override { states.push_back(state); }
};

struct TestSetup {
    FakeClock clock;
    RandomSource random{7};
    DnsQueryFactory queries{random};
    TrafficMeter meter;
    FakeProbe tunnel;
    FakeProbe control;
    ManualScheduler scheduler;
    RecordingListener listener;
    HealthSettings settings{};
    HealthMonitor monitor{settings, listener, meter, tunnel, control, queries, scheduler, clock};

    void arrive(int packets) {
        for (int i = 0; i < packets; ++i) {
            meter.recordInbound(100);
        }
    }
};

constexpr auto kPeriod = std::chrono::milliseconds(10000);

}  // namespace

TEST(HealthPeriod, ZeroAndNegativeSelectTheDefault) {
    EXPECT_EQ(HealthSettings::fromSeconds(0).period, libxtun::health::kDefaultPeriod);
    EXPECT_EQ(HealthSettings::fromSeconds(-1).period, libxtun::health::kDefaultPeriod);
    EXPECT_EQ(HealthSettings::fromSeconds(-3600).period, libxtun::health::kDefaultPeriod);
}

TEST(HealthPeriod, SubFloorValuesAreRaisedRatherThanHonoured) {
    EXPECT_EQ(HealthSettings::fromSeconds(1).period, libxtun::health::kPeriodFloor);
    EXPECT_EQ(HealthSettings::fromSeconds(4).period, libxtun::health::kPeriodFloor);
    EXPECT_EQ(HealthSettings::fromSeconds(5).period, libxtun::health::kPeriodFloor);
}

TEST(HealthPeriod, ConfiguredCadenceAboveTheFloorIsUsedAsGiven) {
    EXPECT_EQ(HealthSettings::fromSeconds(6).period, std::chrono::seconds(6));
    EXPECT_EQ(HealthSettings::fromSeconds(30).period, std::chrono::seconds(30));
    EXPECT_EQ(HealthSettings::fromSeconds(3600).period, std::chrono::seconds(3600));
}

TEST(HealthPeriod, TheRestOfTheSettingsKeepTheirDefaults) {
    const HealthSettings settings = HealthSettings::fromSeconds(30);

    EXPECT_EQ(settings.probe_timeout, libxtun::health::kProbeTimeout);
    EXPECT_EQ(settings.fail_streak, libxtun::health::kFailStreak);
    EXPECT_EQ(settings.no_network_backoff, libxtun::health::kNoNetworkBackoff);
    EXPECT_EQ(settings.jitter_percent, libxtun::health::kJitterPercent);
}

TEST(HealthMonitor, StartArmsTheSchedulerWithThePeriod) {
    TestSetup s;

    s.monitor.start();

    EXPECT_TRUE(s.scheduler.armed());
    EXPECT_EQ(s.scheduler.firstDelay(), kPeriod);
    EXPECT_TRUE(s.monitor.running());
}

TEST(HealthMonitor, NoEvidenceHoldsUnknownAndEmitsNothing) {
    TestSetup s;
    s.monitor.start();

    EXPECT_EQ(s.scheduler.fire(), kPeriod);

    EXPECT_TRUE(s.listener.states.empty()) << "a verdict was emitted with no evidence for it";
    EXPECT_EQ(s.monitor.snapshot().state, ConnectionState::Unknown);
    EXPECT_EQ(s.tunnel.runs, 1);
    EXPECT_EQ(s.control.runs, 0) << "the control probe ran before the tunnel probe failed";
}

TEST(HealthMonitor, RealTrafficSettlesConnectedWithoutProbing) {
    TestSetup s;
    s.monitor.start();
    s.arrive(1);

    EXPECT_EQ(s.scheduler.fire(), kPeriod);

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Connected);
    EXPECT_EQ(s.tunnel.runs, 0) << "a busy connection was probed anyway";
}

TEST(HealthMonitor, EmissionIsEdgeTriggered) {
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

TEST(HealthMonitor, AnsweredTunnelProbeIsConnected) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Answered;
    s.monitor.start();

    s.scheduler.fire();

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Connected);
    EXPECT_EQ(s.control.runs, 0);
}

TEST(HealthMonitor, TheStreakMustBeReachedBeforeTheTunnelIsCalledDead) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Answered;
    s.monitor.start();

    EXPECT_EQ(s.scheduler.fire(), kPeriod);
    EXPECT_TRUE(s.listener.states.empty()) << "one failed probe tore the tunnel down";
    EXPECT_EQ(s.monitor.snapshot().fail_streak, 1);

    EXPECT_FALSE(s.scheduler.fire().has_value()) << "a Disconnected verdict must end the loop";

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::Disconnected);
    EXPECT_FALSE(s.monitor.running());
}

TEST(HealthMonitor, BothPathsSilentIsNoNetworkAndBacksOff) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();

    s.scheduler.fire();
    const auto next = s.scheduler.fire();

    ASSERT_EQ(s.listener.states.size(), 1u);
    EXPECT_EQ(s.listener.states[0], ConnectionState::NoNetwork);
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, kPeriod * s.settings.no_network_backoff);
}

TEST(HealthMonitor, WhileOfflineTheUplinkIsRecheckedBeforeTheTunnel) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();
    s.scheduler.fire();
    s.scheduler.fire();
    ASSERT_EQ(s.monitor.snapshot().state, ConnectionState::NoNetwork);

    const int tunnel_runs = s.tunnel.runs;
    s.scheduler.fire();

    EXPECT_EQ(s.tunnel.runs, tunnel_runs)
        << "the tunnel was probed while the host was known to be offline";
    EXPECT_EQ(s.control.runs, 2);
}

TEST(HealthMonitor, RecoveringFromNoNetworkTakesTheTunnelProbeAgain) {
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

TEST(HealthMonitor, ResetIsSilentAndClearsTheStreak) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Answered;
    s.monitor.start();
    s.scheduler.fire();
    ASSERT_EQ(s.monitor.snapshot().fail_streak, 1);

    s.monitor.requestReset();
    s.scheduler.fire();

    EXPECT_TRUE(s.listener.states.empty()) << "a roam was reported to the client as a state change";
    EXPECT_EQ(s.monitor.snapshot().state, ConnectionState::Unknown);
    EXPECT_EQ(s.monitor.snapshot().fail_streak, 0);
}

TEST(HealthMonitor, TrafficFromBeforeARoamCannotSatisfyTheFreshnessRule) {
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

TEST(HealthMonitor, TheInboundMarkAdvancesOnEveryTickIncludingEarlyReturns) {
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

TEST(HealthMonitor, SuspendClearsTheStateWithoutTellingTheClient) {
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

TEST(HealthMonitor, UnknownIsNeverEmitted) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Answered;
    s.monitor.start();
    s.scheduler.fire();

    s.monitor.requestReset();
    s.scheduler.fire();
    s.clock.advanceWallOnly(std::chrono::seconds(60));
    s.scheduler.fire();

    EXPECT_TRUE(std::none_of(s.listener.states.begin(), s.listener.states.end(),
                             [](ConnectionState state) {
                                 return state == ConnectionState::Unknown;
                             }))
        << "Unknown has no libxtun_status to map to and must never reach the client";
}

TEST(HealthMonitor, EveryProbeGetsItsOwnQuery) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.control.outcome = ProbeOutcome::Failed;
    s.monitor.start();

    s.scheduler.fire();
    s.scheduler.fire();

    ASSERT_GE(s.tunnel.ports.size(), 2u);
    ASSERT_GE(s.control.ports.size(), 1u);
    EXPECT_NE(s.tunnel.ports[0], s.tunnel.ports[1]) << "two probes shared a source port";
    EXPECT_NE(s.tunnel.ports[1], s.control.ports[0])
        << "the tunnel and control probes shared one query";
}

TEST(HealthMonitor, TheSnapshotCarriesTheCountersAndTheStreak) {
    TestSetup s;
    s.tunnel.outcome = ProbeOutcome::Failed;
    s.monitor.start();
    s.arrive(3);
    s.meter.recordOutbound(40);

    s.scheduler.fire();

    const auto snapshot = s.monitor.snapshot();
    EXPECT_EQ(snapshot.state, ConnectionState::Connected);
    EXPECT_EQ(snapshot.traffic.inbound_packets, 3u);
    EXPECT_EQ(snapshot.traffic.inbound_bytes, 300u);
    EXPECT_EQ(snapshot.traffic.outbound_packets, 1u);
    EXPECT_EQ(snapshot.fail_streak, 0);
    EXPECT_FALSE(snapshot.probe_pending);
    EXPECT_EQ(snapshot.last_inbound_seen, s.clock.steadyNow());
}

TEST(HealthMonitor, SnapshotReportsProbePendingOnlyWhileProbeRuns) {
    TestSetup s;
    bool pending_during_probe = false;
    s.tunnel.while_running = [&] { pending_during_probe = s.monitor.snapshot().probe_pending; };
    s.monitor.start();

    s.scheduler.fire();

    EXPECT_TRUE(pending_during_probe) << "a caller polling the snapshot never sees a probe in flight";
    EXPECT_FALSE(s.monitor.snapshot().probe_pending) << "probe_pending stayed set after the probe";
}

TEST(HealthMonitor, StoppingStopsTheScheduler) {
    TestSetup s;
    s.monitor.start();

    s.monitor.stop();

    EXPECT_FALSE(s.monitor.running());
    EXPECT_EQ(s.scheduler.stops(), 1);
}

TEST(HealthMonitor, TheMonitorItselfNeitherEmitsToTheAbiNorTearsAnythingDown) {
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
