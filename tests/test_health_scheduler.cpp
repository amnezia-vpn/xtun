#include "health/scheduler.h"
#include "util/random.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{

    using libxtun::RandomSource;
    using libxtun::health::ThreadedScheduler;
    using namespace std::chrono_literals;

    bool waitUntil(const std::function<bool()> &done, std::chrono::milliseconds timeout = 2s)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (done()) {
                return true;
            }
            std::this_thread::sleep_for(1ms);
        }
        return done();
    }

    class LogCollector
    {
    public:
        void operator()(const char *message)
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_lines.emplace_back(message);
        }

        std::vector<std::string> lines() const
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            return m_lines;
        }

    private:
        mutable std::mutex m_mtx;
        std::vector<std::string> m_lines;
    };

} // namespace

TEST(HealthScheduler, RunsTheTickAndHonoursTheReturnedDelay)
{
    RandomSource random(1);
    ThreadedScheduler scheduler(random, 0);
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++ticks;
                return 5ms;
            },
            0ms);

    EXPECT_TRUE(waitUntil([&] { return ticks.load() >= 3; }));
    EXPECT_TRUE(scheduler.running());
}

TEST(HealthScheduler, NulloptEndsTheLoopWithoutAnyoneJoining)
{
    RandomSource random(1);
    ThreadedScheduler scheduler(random, 0);
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++ticks;
                return std::nullopt;
            },
            0ms);

    EXPECT_TRUE(waitUntil([&] { return !scheduler.running(); }));
    EXPECT_EQ(ticks.load(), 1) << "the loop kept running after asking to stop";
}

TEST(HealthScheduler, StopFromInsideTheTickDoesNotSelfJoin)
{
    RandomSource random(1);
    ThreadedScheduler scheduler(random, 0);
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++ticks;
                scheduler.stop();
                return 5ms;
            },
            0ms);

    EXPECT_TRUE(waitUntil([&] { return !scheduler.running(); }));
    EXPECT_EQ(ticks.load(), 1);
}

TEST(HealthScheduler, StopFromAnotherThreadJoinsAndIsIdempotent)
{
    RandomSource random(1);
    ThreadedScheduler scheduler(random, 0);
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++ticks;
                return 1ms;
            },
            0ms);
    ASSERT_TRUE(waitUntil([&] { return ticks.load() >= 1; }));

    scheduler.stop();
    const int afterStop = ticks.load();
    scheduler.stop();

    EXPECT_FALSE(scheduler.running());
    std::this_thread::sleep_for(20ms);
    EXPECT_EQ(ticks.load(), afterStop) << "the tick ran after the scheduler was stopped";
}

TEST(HealthScheduler, WakeEvaluatesImmediatelyInsteadOfWaitingOutThePeriod)
{
    RandomSource random(1);
    ThreadedScheduler scheduler(random, 0);
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++ticks;
                return 1h;
            },
            1h);

    EXPECT_FALSE(waitUntil([&] { return ticks.load() >= 1; }, 30ms));
    scheduler.wake();
    EXPECT_TRUE(waitUntil([&] { return ticks.load() >= 1; }));
}

TEST(HealthScheduler, ThrowingTickIsContainedAndTheCadenceSurvives)
{
    RandomSource random(1);
    LogCollector log;
    ThreadedScheduler scheduler(random, 0, [&log](const char *message) { log(message); });
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                if (++ticks == 1) {
                    throw std::runtime_error("probe exploded");
                }
                return 2ms;
            },
            0ms);

    EXPECT_TRUE(waitUntil([&] { return ticks.load() >= 3; })) << "one throwing tick killed the cadence";
    EXPECT_TRUE(scheduler.running());

    const auto lines = log.lines();
    ASSERT_FALSE(lines.empty()) << "the contained exception was never reported";
    EXPECT_EQ(lines[0], "probe exploded");
}

TEST(HealthScheduler, NonStandardThrowIsAlsoContained)
{
    RandomSource random(1);
    LogCollector log;
    ThreadedScheduler scheduler(random, 0, [&log](const char *message) { log(message); });
    std::atomic<int> ticks { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                if (++ticks == 1) {
                    throw 42;
                }
                return 2ms;
            },
            0ms);

    EXPECT_TRUE(waitUntil([&] { return ticks.load() >= 2; }));
    EXPECT_FALSE(log.lines().empty());
}

TEST(HealthScheduler, JitterKeepsTheDelayPositiveAndNearThePeriod)
{
    RandomSource random(99);
    ThreadedScheduler scheduler(random, 20);
    std::atomic<int> ticks { 0 };

    const auto started = std::chrono::steady_clock::now();
    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++ticks;
                return 40ms;
            },
            40ms);

    ASSERT_TRUE(waitUntil([&] { return ticks.load() >= 3; }));
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_GE(elapsed, 3 * 32ms) << "jitter collapsed the delay towards zero";
    EXPECT_LT(elapsed, 2s);
}

TEST(HealthScheduler, DestructionJoinsAThreadThatEndedItsOwnLoop)
{
    RandomSource random(1);
    std::atomic<int> ticks { 0 };
    {
        ThreadedScheduler scheduler(random, 0);
        scheduler.start(
                [&]() -> std::optional<std::chrono::milliseconds> {
                    ++ticks;
                    return std::nullopt;
                },
                0ms);
        ASSERT_TRUE(waitUntil([&] { return !scheduler.running(); }));
    }

    EXPECT_EQ(ticks.load(), 1);
}

TEST(HealthScheduler, StartingAgainReplacesTheTick)
{
    RandomSource random(1);
    ThreadedScheduler scheduler(random, 0);
    std::atomic<int> first { 0 };
    std::atomic<int> second { 0 };

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++first;
                return 1ms;
            },
            0ms);
    ASSERT_TRUE(waitUntil([&] { return first.load() >= 1; }));

    scheduler.start(
            [&]() -> std::optional<std::chrono::milliseconds> {
                ++second;
                return 1ms;
            },
            0ms);
    ASSERT_TRUE(waitUntil([&] { return second.load() >= 2; }));

    const int frozen = first.load();
    std::this_thread::sleep_for(20ms);
    EXPECT_EQ(first.load(), frozen) << "the replaced tick was still being called";
}
