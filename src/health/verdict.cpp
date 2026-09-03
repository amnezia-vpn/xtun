#include "verdict.h"

namespace libxtun::health
{

    SuspendDetector::SuspendDetector(const Clock &clock, std::chrono::seconds tolerance) noexcept
        : m_clock(clock), m_tolerance(tolerance), m_lastSteady(clock.steadyNow()), m_lastWall(clock.wallNow())
    {
    }

    bool SuspendDetector::sample()
    {
        const auto steady = m_clock.steadyNow();
        const auto wall = m_clock.wallNow();

        const auto steadyElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(steady - m_lastSteady);
        const auto wallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(wall - m_lastWall);

        m_lastSteady = steady;
        m_lastWall = wall;

        const auto divergence =
                wallElapsed > steadyElapsed ? wallElapsed - steadyElapsed : steadyElapsed - wallElapsed;
        return divergence > std::chrono::duration_cast<std::chrono::milliseconds>(m_tolerance);
    }

}
