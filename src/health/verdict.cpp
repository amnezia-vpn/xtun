#include "verdict.h"

namespace libxtun::health {

SuspendDetector::SuspendDetector(const Clock &clock, std::chrono::seconds tolerance) noexcept
    : m_clock(clock),
      m_tolerance(tolerance),
      m_last_steady(clock.steadyNow()),
      m_last_wall(clock.wallNow()) {}

bool SuspendDetector::sample() {
    const auto steady = m_clock.steadyNow();
    const auto wall = m_clock.wallNow();

    const auto steady_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(steady - m_last_steady);
    const auto wall_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(wall - m_last_wall);

    m_last_steady = steady;
    m_last_wall = wall;

    const auto divergence = wall_elapsed > steady_elapsed ? wall_elapsed - steady_elapsed
                                                          : steady_elapsed - wall_elapsed;
    return divergence > std::chrono::duration_cast<std::chrono::milliseconds>(m_tolerance);
}

}
