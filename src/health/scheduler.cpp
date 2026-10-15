#include "scheduler.h"

#include "util/random.h"
#include <utility>

namespace libxtun::health
{
    ThreadedScheduler::ThreadedScheduler(int jitterPercent) : m_jitterPercent(jitterPercent)
    {
    }

    ThreadedScheduler::~ThreadedScheduler()
    {
        stop();
    }

    void ThreadedScheduler::start(Tick tick, std::chrono::milliseconds firstDelay)
    {
        stop();

        std::lock_guard<std::mutex> lock(m_mtx);
        m_tick = std::move(tick);
        m_stop = false;
        m_wake = false;
        m_running = true;
        m_thread = std::thread(&ThreadedScheduler::loop, this, firstDelay);
    }

    void ThreadedScheduler::stop() noexcept
    {
        std::thread ended;
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_stop = true;
            m_cond.notify_all();
            if (m_thread.joinable() && m_thread.get_id() != std::this_thread::get_id()) {
                ended = std::move(m_thread);
            }
        }
        if (ended.joinable()) {
            ended.join();
        }
    }

    void ThreadedScheduler::wake()
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_wake = true;
        m_cond.notify_all();
    }

    bool ThreadedScheduler::running() const noexcept
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_running;
    }

    void ThreadedScheduler::loop(std::chrono::milliseconds firstDelay)
    {
        std::unique_lock<std::mutex> lock(m_mtx);
        std::chrono::milliseconds delay = firstDelay;

        for (;;) {
            m_cond.wait_for(lock, withJitter(delay), [this] { return m_stop || m_wake; });
            if (m_stop) {
                break;
            }
            m_wake = false;

            const Tick tick = m_tick;
            lock.unlock();
            const auto next = runTick(tick);
            lock.lock();

            if (!next.has_value()) {
                break;
            }
            delay = *next;
        }
        m_running = false;
    }

    std::optional<std::chrono::milliseconds> ThreadedScheduler::runTick(const Tick &tick) noexcept
    {
        return tick();
    }

    std::chrono::milliseconds ThreadedScheduler::withJitter(std::chrono::milliseconds base)
    {
        if (m_jitterPercent <= 0 || base <= std::chrono::milliseconds::zero()) {
            return base;
        }
        const auto span = static_cast<int>(base.count() * m_jitterPercent / 100);
        return base + std::chrono::milliseconds(rand::nexti(-span, span));
    }
}
