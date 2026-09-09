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

namespace
{

    using libxtun::IO_FATAL;
    using libxtun::READ_WAKE;

    class FakeDevice final : public libxtun::TunnelIo
    {
    public:
        std::deque<int> reads;
        std::vector<std::vector<std::byte>> writes;

        int read(std::span<std::byte> buf) noexcept override
        {
            if (reads.empty()) {
                return IO_FATAL;
            }
            const int n = reads.front();
            reads.pop_front();
            if (n > 0) {
                std::fill_n(buf.begin(), std::min<std::size_t>(n, buf.size()), std::byte { 0xab });
            }
            return n;
        }

        int write(std::span<const std::byte> packet) noexcept override
        {
            writes.emplace_back(packet.begin(), packet.end());
            return static_cast<int>(packet.size());
        }

        int mtu() const noexcept override
        {
            return 1280;
        }

        void protectSocket(int fd) override
        {
        }

        void halt() override
        {
        }
    };

    class FakeInterceptor final : public libxtun::health::PacketInterceptor
    {
    public:
        int stageBytes = 0;
        bool captureNext = false;
        int stageCalls = 0;
        std::vector<std::vector<std::byte>> captured;

        int stage(std::span<std::byte> buf) noexcept override
        {
            ++stageCalls;
            if (stageBytes <= 0) {
                return 0;
            }
            const int n = std::min<int>(stageBytes, static_cast<int>(buf.size()));
            std::fill_n(buf.begin(), n, std::byte { 0xcd });
            stageBytes = 0;
            return n;
        }

        bool capture(std::span<const std::byte> packet) noexcept override
        {
            if (!captureNext) {
                return false;
            }
            captured.emplace_back(packet.begin(), packet.end());
            captureNext = false;
            return true;
        }
    };

    struct TestSetup
    {
        FakeDevice device;
        libxtun::health::TrafficMeter meter;
        FakeInterceptor interceptor;
        libxtun::health::MonitoredIo io { device, meter, interceptor };

        std::array<std::byte, 64> buf {};
    };

} // namespace

TEST(HealthMonitoredIo, ReadsCountAsOutboundTraffic)
{
    TestSetup s;
    s.device.reads = { 40 };

    EXPECT_EQ(s.io.read(s.buf), 40);

    const auto counters = s.meter.counters();
    EXPECT_EQ(counters.outboundPackets, 1u);
    EXPECT_EQ(counters.outboundBytes, 40u);
    EXPECT_EQ(counters.inboundPackets, 0u);
    EXPECT_EQ(s.meter.inboundPackets(), 0u);
}

TEST(HealthMonitoredIo, WritesCountAsInboundTraffic)
{
    TestSetup s;

    EXPECT_EQ(s.io.write(std::span<const std::byte>(s.buf.data(), 32)), 32);

    const auto counters = s.meter.counters();
    EXPECT_EQ(counters.inboundPackets, 1u);
    EXPECT_EQ(counters.inboundBytes, 32u);
    EXPECT_EQ(counters.outboundPackets, 0u);
    EXPECT_EQ(s.meter.inboundPackets(), 1u);
    ASSERT_EQ(s.device.writes.size(), 1u);
}

TEST(HealthMonitoredIo, SpuriousWakeReadsAgainInsteadOfReturningZero)
{
    TestSetup s;
    s.device.reads = { READ_WAKE, 20 };

    EXPECT_EQ(s.io.read(s.buf), 20);
    EXPECT_EQ(s.interceptor.stageCalls, 1);
    EXPECT_TRUE(s.device.reads.empty());
}

TEST(HealthMonitoredIo, StagedProbeIsReturnedAndNotMetered)
{
    TestSetup s;
    s.device.reads = { READ_WAKE };
    s.interceptor.stageBytes = 12;

    EXPECT_EQ(s.io.read(s.buf), 12);
    EXPECT_EQ(s.meter.counters().outboundPackets, 0u);
}

TEST(HealthMonitoredIo, CapturedReplyNeverReachesTheDeviceOrTheMeter)
{
    TestSetup s;
    s.interceptor.captureNext = true;

    EXPECT_EQ(s.io.write(std::span<const std::byte>(s.buf.data(), 24)), 24);

    EXPECT_TRUE(s.device.writes.empty()) << "the stolen reply was written to the tun";
    EXPECT_EQ(s.meter.inboundPackets(), 0u);
    ASSERT_EQ(s.interceptor.captured.size(), 1u);
    EXPECT_EQ(s.interceptor.captured[0].size(), 24u);
}

TEST(HealthMonitoredIo, HaltLatchesBothDirections)
{
    TestSetup s;
    s.device.reads = { 40 };

    s.io.halt();

    EXPECT_TRUE(s.io.halted());
    EXPECT_EQ(s.io.read(s.buf), IO_FATAL);
    EXPECT_EQ(s.io.write(std::span<const std::byte>(s.buf.data(), 24)), IO_FATAL);
    EXPECT_TRUE(s.device.writes.empty());
    EXPECT_EQ(s.device.reads.size(), 1u) << "the device was read after the decorator was halted";
}

TEST(HealthMonitoredIo, FatalDeviceReadPropagates)
{
    TestSetup s;

    EXPECT_EQ(s.io.read(s.buf), IO_FATAL);
    EXPECT_EQ(s.meter.counters().outboundPackets, 0u);
}

TEST(HealthMonitoredIo, MtuIsForwardedToTheDevice)
{
    TestSetup s;

    EXPECT_EQ(s.io.mtu(), s.device.mtu());
}
