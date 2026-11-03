#include "io/awaiting_io.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>

namespace
{
    using namespace std::chrono_literals;

    // Keep a read active after wake() until the test allows its final packet to return.
    class BlockingIo final : public libxtun::TunnelIo
    {
    public:
        int read(std::span<std::byte> buffer) override
        {
            std::unique_lock lock(m_mutex);
            m_readStarted = true;
            m_cv.notify_all();
            if (!m_cv.wait_for(lock, 5s, [this] { return m_released; })) {
                return libxtun::IO_FATAL;
            }
            buffer.front() = std::byte { 42 };
            return 1;
        }

        int write(std::span<const std::byte> packet) override
        {
            return static_cast<int>(packet.size());
        }

        void wake() override
        {
            std::lock_guard lock(m_mutex);
            m_woken = true;
            m_cv.notify_all();
        }

        void halt() override
        {
            release();
        }

        int mtu() const override
        {
            return 1500;
        }

        std::vector<libxtun::net::IpPrefix> addresses() override
        {
            return {};
        }

        libxtun_error protectSocket(int) override
        {
            return LIBXTUN_OK;
        }

        bool waitForRead()
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, 2s, [this] { return m_readStarted; });
        }

        bool waitForWake()
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, 2s, [this] { return m_woken; });
        }

        void release()
        {
            std::lock_guard lock(m_mutex);
            m_released = true;
            m_cv.notify_all();
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_readStarted = false;
        bool m_woken = false;
        bool m_released = false;
    };
}

TEST(AwaitingIo, WakeDiscardsTheInterruptedPacketAndAllowsFurtherIo)
{
    BlockingIo device;
    libxtun::AwaitingIo io(&device);
    std::array<std::byte, 1> buffer;
    auto reading = std::async(std::launch::async, [&] { return io.read(buffer); });
    EXPECT_TRUE(device.waitForRead());

    io.wake();
    device.release();
    EXPECT_EQ(reading.get(), libxtun::READ_WAKE);
    EXPECT_EQ(io.read(buffer), 1);
    EXPECT_EQ(buffer.front(), std::byte { 42 });
    EXPECT_EQ(io.write(buffer), 1);
}

TEST(AwaitingIo, DetachWaitsForTheActiveReadAndAllowsReattachment)
{
    BlockingIo device;
    libxtun::AwaitingIo io(&device);
    std::array<std::byte, 1> buffer;
    auto reading = std::async(std::launch::async, [&] { return io.read(buffer); });
    EXPECT_TRUE(device.waitForRead());
    auto detaching = std::async(std::launch::async, [&] { io.assign(nullptr); });
    EXPECT_TRUE(device.waitForWake());
    EXPECT_EQ(detaching.wait_for(50ms), std::future_status::timeout);

    device.release();
    EXPECT_EQ(reading.get(), libxtun::READ_WAKE);
    detaching.get();
    EXPECT_EQ(io.protectSocket(42), LIBXTUN_ERR_UNSUPPORTED);
    io.assign(&device);
    EXPECT_EQ(io.read(buffer), 1);
    EXPECT_EQ(io.protectSocket(42), LIBXTUN_OK);
}

TEST(AwaitingIo, HaltWaitsForTheActiveReadAndRejectsFurtherIo)
{
    BlockingIo device;
    libxtun::AwaitingIo io(&device);
    std::array<std::byte, 1> buffer;
    auto reading = std::async(std::launch::async, [&] { return io.read(buffer); });
    EXPECT_TRUE(device.waitForRead());
    auto stopping = std::async(std::launch::async, [&] { io.halt(); });
    EXPECT_TRUE(device.waitForWake());
    EXPECT_EQ(stopping.wait_for(50ms), std::future_status::timeout);

    device.release();
    EXPECT_EQ(reading.get(), libxtun::IO_FATAL);
    stopping.get();
    EXPECT_EQ(io.read(buffer), libxtun::IO_FATAL);
    EXPECT_EQ(io.write(buffer), libxtun::IO_FATAL);
    EXPECT_EQ(io.protectSocket(42), LIBXTUN_ERR_UNSUPPORTED);
}
