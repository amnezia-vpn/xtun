#ifndef TESTS_HEALTH_FAKE_CLOCK_H
#define TESTS_HEALTH_FAKE_CLOCK_H

#include "util/clock.h"

#include <chrono>

class FakeClock final : public libxtun::Clock
{
public:
    std::chrono::steady_clock::time_point steadyNow() const noexcept override
    {
        return m_steady;
    }
    std::chrono::system_clock::time_point wallNow() const noexcept override
    {
        return m_wall;
    }

    void advance(std::chrono::milliseconds delta)
    {
        m_steady += delta;
        m_wall += delta;
    }

    void advanceSteadyOnly(std::chrono::milliseconds delta)
    {
        m_steady += delta;
    }
    void advanceWallOnly(std::chrono::milliseconds delta)
    {
        m_wall += delta;
    }

private:
    std::chrono::steady_clock::time_point m_steady { std::chrono::steady_clock::duration { 1 } };
    std::chrono::system_clock::time_point m_wall { std::chrono::system_clock::duration { 1 } };
};

#endif // TESTS_HEALTH_FAKE_CLOCK_H
