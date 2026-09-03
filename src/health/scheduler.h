#ifndef HEALTH_SCHEDULER_H
#define HEALTH_SCHEDULER_H

#include "health/state.h"
#include "util/noncopyable.h"
#include "util/random.h"

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

namespace libxtun::health
{

    class Scheduler
    {
    public:
        using Tick = std::function<std::optional<std::chrono::milliseconds>()>;

        virtual ~Scheduler() = default;

        virtual void start(Tick tick, std::chrono::milliseconds first_delay) = 0;
        virtual void stop() noexcept = 0;
        virtual void wake() = 0;
        virtual bool running() const noexcept = 0;
    };

    class ThreadedScheduler final : public Scheduler, private NonCopyable
    {
    public:
        ThreadedScheduler(RandomSource &random, int jitter_percent, LogSink log = {});
        ~ThreadedScheduler() override;

        void start(Tick tick, std::chrono::milliseconds first_delay) override;
        void stop() noexcept override;
        void wake() override;
        bool running() const noexcept override;

    private:
        void loop(std::chrono::milliseconds first_delay);
        std::chrono::milliseconds withJitter(std::chrono::milliseconds base);
        std::optional<std::chrono::milliseconds> runTick(const Tick &tick, std::chrono::milliseconds fallback) noexcept;

        Tick m_tick;
        RandomSource &m_random;
        int m_jitter_percent;
        LogSink m_log;

        mutable std::mutex m_mtx;
        std::condition_variable m_cond;
        std::thread m_thread;
        bool m_running = false;
        bool m_stop = false;
        bool m_wake = false;
    };

}

#endif // HEALTH_SCHEDULER_H
