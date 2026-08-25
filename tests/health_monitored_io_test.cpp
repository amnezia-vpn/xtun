#include "health/monitored_io.h"
#include "health/traffic_meter.h"
#include "tunnel_io.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <span>
#include <vector>

namespace {

using libxtun::kIoFatal;
using libxtun::kReadWake;

class FakeDevice final : public libxtun::TunnelIo {
  public:
    std::deque<int> reads;
    std::vector<std::vector<std::byte>> writes;

    int read(std::span<std::byte> buf) noexcept override {
        if (reads.empty()) {
            return kIoFatal;
        }
        const int n = reads.front();
        reads.pop_front();
        if (n > 0) {
            std::fill_n(buf.begin(), std::min<std::size_t>(n, buf.size()), std::byte{0xab});
        }
        return n;
    }

    int write(std::span<const std::byte> packet) noexcept override {
        writes.emplace_back(packet.begin(), packet.end());
        return static_cast<int>(packet.size());
    }

    int mtu() const noexcept override { return 1280; }
};

class FakeInterceptor final : public libxtun::health::PacketInterceptor {
  public:
    int stage_bytes = 0;
    bool capture_next = false;
    int stage_calls = 0;
    std::vector<std::vector<std::byte>> captured;

    int stage(std::span<std::byte> buf) noexcept override {
        ++stage_calls;
        if (stage_bytes <= 0) {
            return 0;
        }
        const int n = std::min<int>(stage_bytes, static_cast<int>(buf.size()));
        std::fill_n(buf.begin(), n, std::byte{0xcd});
        stage_bytes = 0;
        return n;
    }

    bool capture(std::span<const std::byte> packet) noexcept override {
        if (!capture_next) {
            return false;
        }
        captured.emplace_back(packet.begin(), packet.end());
        capture_next = false;
        return true;
    }
};

struct TestSetup {
    FakeDevice device;
    libxtun::health::TrafficMeter meter;
    FakeInterceptor interceptor;
    libxtun::health::MonitoredIo io{device, meter, interceptor};

    std::array<std::byte, 64> buf{};
};

}  // namespace

TEST(HealthMonitoredIo, ReadsCountAsOutboundTraffic) {
    TestSetup s;
    s.device.reads = {40};

    EXPECT_EQ(s.io.read(s.buf), 40);

    const auto counters = s.meter.counters();
    EXPECT_EQ(counters.outbound_packets, 1u);
    EXPECT_EQ(counters.outbound_bytes, 40u);
    EXPECT_EQ(counters.inbound_packets, 0u);
    EXPECT_EQ(s.meter.inboundPackets(), 0u);
}

TEST(HealthMonitoredIo, WritesCountAsInboundTraffic) {
    TestSetup s;

    EXPECT_EQ(s.io.write(std::span<const std::byte>(s.buf.data(), 32)), 32);

    const auto counters = s.meter.counters();
    EXPECT_EQ(counters.inbound_packets, 1u);
    EXPECT_EQ(counters.inbound_bytes, 32u);
    EXPECT_EQ(counters.outbound_packets, 0u);
    EXPECT_EQ(s.meter.inboundPackets(), 1u);
    ASSERT_EQ(s.device.writes.size(), 1u);
}

TEST(HealthMonitoredIo, SpuriousWakeReadsAgainInsteadOfReturningZero) {
    TestSetup s;
    s.device.reads = {kReadWake, 20};

    EXPECT_EQ(s.io.read(s.buf), 20);
    EXPECT_EQ(s.interceptor.stage_calls, 1);
    EXPECT_TRUE(s.device.reads.empty());
}

TEST(HealthMonitoredIo, StagedProbeIsReturnedAndNotMetered) {
    TestSetup s;
    s.device.reads = {kReadWake};
    s.interceptor.stage_bytes = 12;

    EXPECT_EQ(s.io.read(s.buf), 12);
    EXPECT_EQ(s.meter.counters().outbound_packets, 0u);
}

TEST(HealthMonitoredIo, CapturedReplyNeverReachesTheDeviceOrTheMeter) {
    TestSetup s;
    s.interceptor.capture_next = true;

    EXPECT_EQ(s.io.write(std::span<const std::byte>(s.buf.data(), 24)), 24);

    EXPECT_TRUE(s.device.writes.empty()) << "the stolen reply was written to the tun";
    EXPECT_EQ(s.meter.inboundPackets(), 0u);
    ASSERT_EQ(s.interceptor.captured.size(), 1u);
    EXPECT_EQ(s.interceptor.captured[0].size(), 24u);
}

TEST(HealthMonitoredIo, HaltLatchesBothDirections) {
    TestSetup s;
    s.device.reads = {40};

    s.io.halt();

    EXPECT_TRUE(s.io.halted());
    EXPECT_EQ(s.io.read(s.buf), kIoFatal);
    EXPECT_EQ(s.io.write(std::span<const std::byte>(s.buf.data(), 24)), kIoFatal);
    EXPECT_TRUE(s.device.writes.empty());
    EXPECT_EQ(s.device.reads.size(), 1u) << "the device was read after the decorator was halted";
}

TEST(HealthMonitoredIo, FatalDeviceReadPropagates) {
    TestSetup s;

    EXPECT_EQ(s.io.read(s.buf), kIoFatal);
    EXPECT_EQ(s.meter.counters().outbound_packets, 0u);
}

TEST(HealthMonitoredIo, MtuIsForwardedToTheDevice) {
    TestSetup s;

    EXPECT_EQ(s.io.mtu(), s.device.mtu());
}
