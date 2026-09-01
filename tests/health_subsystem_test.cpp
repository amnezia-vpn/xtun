#include "health/subsystem.h"
#include "injectable_tun.h"
#include "tunnel_io.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using libxtun::health::ConnectionState;
using libxtun::health::HealthConfig;
using libxtun::health::HealthListener;
using libxtun::health::HealthSubsystem;
using namespace std::chrono_literals;

class SilentListener final : public HealthListener {
  public:
    void onConnectionState(ConnectionState) noexcept override { ++m_calls; }

    int calls() const { return m_calls.load(); }

  private:
    std::atomic<int> m_calls{0};
};

class WakeCounter {
  public:
    void record() {
        std::lock_guard<std::mutex> lock(m_mtx);
        ++m_count;
        m_cond.notify_all();
    }

    bool await(int at_least, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(m_mtx);
        return m_cond.wait_for(lock, timeout, [this, at_least] { return m_count >= at_least; });
    }

    int count() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_count;
    }

  private:
    mutable std::mutex m_mtx;
    std::condition_variable m_cond;
    int m_count = 0;
};

HealthConfig routedConfig(WakeCounter &wakes, std::chrono::milliseconds probe_timeout) {
    HealthConfig config;
    config.dns_servers = {"10.8.0.1"};
    config.tunnel_addresses = {"10.8.0.2/24"};
    config.tunnel_routes = {"10.8.0.0/24"};
    config.settings.period = 1s;
    config.settings.probe_timeout = probe_timeout;
    config.settings.jitter_percent = 0;
    config.wake_read = [&wakes] { wakes.record(); };
    return config;
}

constexpr auto kProbeTimeout = 100ms;
constexpr auto kReachTimeout = 5s;
constexpr auto kIdleWindow = 1500ms;

}  // namespace

TEST(HealthSubsystem, DecorateReturnsOwnIoOverDevice) {
    InjectableTun device;
    SilentListener listener;
    WakeCounter wakes;
    HealthSubsystem subsystem(listener, routedConfig(wakes, kProbeTimeout));

    libxtun::TunnelIo &io = subsystem.decorate(device);

    EXPECT_NE(&io, &device) << "the proxy was handed the raw device";
    EXPECT_EQ(io.mtu(), device.mtu());

    std::array<std::byte, 8> packet{};
    EXPECT_EQ(io.write(packet), static_cast<int>(packet.size()));
    EXPECT_EQ(device.written(), 1u);
}

TEST(HealthSubsystem, HaltEndsIoAndIsHarmlessBeforeDecorate) {
    InjectableTun device;
    SilentListener listener;
    WakeCounter wakes;
    HealthSubsystem subsystem(listener, routedConfig(wakes, kProbeTimeout));

    subsystem.halt();
    libxtun::TunnelIo &io = subsystem.decorate(device);

    std::array<std::byte, 8> packet{};
    ASSERT_EQ(io.write(packet), static_cast<int>(packet.size()))
        << "halting before decorate poisoned the io that came after it";

    subsystem.halt();

    EXPECT_EQ(io.write(packet), libxtun::kIoFatal);
    EXPECT_EQ(io.read(packet), libxtun::kIoFatal);
    EXPECT_EQ(device.written(), 1u) << "the device was written to after the halt";
}

TEST(HealthSubsystem, StartDrivesProbeAndStopEndsCadence) {
    InjectableTun device;
    SilentListener listener;
    WakeCounter wakes;
    HealthSubsystem subsystem(listener, routedConfig(wakes, kProbeTimeout));
    static_cast<void>(subsystem.decorate(device));

    subsystem.start();
    ASSERT_TRUE(wakes.await(1, kReachTimeout)) << "the monitor never reached the tunnel probe";

    subsystem.stop();
    const int settled = wakes.count();
    std::this_thread::sleep_for(kIdleWindow);

    EXPECT_EQ(wakes.count(), settled) << "the monitor kept probing after it was stopped";
    device.cancel();
}

TEST(HealthSubsystem, StopReturnsWhileProbeIsStillWaitingForAnswer) {
    InjectableTun device;
    SilentListener listener;
    WakeCounter wakes;
    HealthSubsystem subsystem(listener, routedConfig(wakes, 30s));
    static_cast<void>(subsystem.decorate(device));

    subsystem.start();
    ASSERT_TRUE(wakes.await(1, kReachTimeout)) << "the probe never went out";

    const auto started = std::chrono::steady_clock::now();
    subsystem.stop();
    const auto took = std::chrono::steady_clock::now() - started;

    EXPECT_LT(took, kReachTimeout) << "stop waited out the probe instead of aborting it";
    EXPECT_EQ(listener.calls(), 0) << "a teardown was reported to the client as a state change";
    device.cancel();
}

TEST(HealthSubsystem, NetworkChangeKeepsMonitorRunning) {
    InjectableTun device;
    SilentListener listener;
    WakeCounter wakes;
    HealthSubsystem subsystem(listener, routedConfig(wakes, kProbeTimeout));
    static_cast<void>(subsystem.decorate(device));

    subsystem.onNetworkChanged();
    subsystem.start();
    subsystem.onNetworkChanged();

    EXPECT_TRUE(wakes.await(1, kReachTimeout)) << "the monitor stopped probing after a roam";

    subsystem.stop();
    device.cancel();
}

TEST(HealthSubsystem, DestructionStopsRunningMonitor) {
    InjectableTun device;
    SilentListener listener;
    WakeCounter wakes;
    {
        HealthSubsystem subsystem(listener, routedConfig(wakes, kProbeTimeout));
        static_cast<void>(subsystem.decorate(device));
        subsystem.start();
        ASSERT_TRUE(wakes.await(1, kReachTimeout));
    }

    const int settled = wakes.count();
    std::this_thread::sleep_for(kIdleWindow);

    EXPECT_EQ(wakes.count(), settled) << "the monitor outlived the subsystem that owns it";
    device.cancel();
}
