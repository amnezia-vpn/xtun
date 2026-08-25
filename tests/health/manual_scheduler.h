#ifndef TESTS_HEALTH_MANUAL_SCHEDULER_H
#define TESTS_HEALTH_MANUAL_SCHEDULER_H

#include "health/scheduler.h"

#include <chrono>
#include <optional>
#include <utility>

class ManualScheduler final : public libxtun::health::Scheduler {
  public:
    void start(Tick tick, std::chrono::milliseconds first_delay) override {
        m_tick = std::move(tick);
        m_first_delay = first_delay;
        m_running = true;
        ++m_starts;
    }

    void stop() noexcept override {
        m_running = false;
        ++m_stops;
    }

    void wake() override { ++m_wakes; }

    bool running() const noexcept override { return m_running; }

    std::optional<std::chrono::milliseconds> fire() {
        const auto next = m_tick();
        if (!next.has_value()) {
            m_running = false;
        }
        return next;
    }

    bool armed() const { return static_cast<bool>(m_tick); }
    std::chrono::milliseconds firstDelay() const { return m_first_delay; }
    int starts() const { return m_starts; }
    int stops() const { return m_stops; }
    int wakes() const { return m_wakes; }

  private:
    Tick m_tick;
    std::chrono::milliseconds m_first_delay{0};
    bool m_running = false;
    int m_starts = 0;
    int m_stops = 0;
    int m_wakes = 0;
};

#endif // TESTS_HEALTH_MANUAL_SCHEDULER_H
