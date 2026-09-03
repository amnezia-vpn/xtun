#ifndef CLOCK_H
#define CLOCK_H

#include <chrono>

namespace libxtun
{

    class Clock
    {
    public:
        virtual ~Clock() = default;

        virtual std::chrono::steady_clock::time_point steadyNow() const noexcept = 0;
        virtual std::chrono::system_clock::time_point wallNow() const noexcept = 0;
    };

    class RealClock final : public Clock
    {
    public:
        static const RealClock &instance() noexcept
        {
            static const RealClock clock;
            return clock;
        }

        std::chrono::steady_clock::time_point steadyNow() const noexcept override
        {
            return std::chrono::steady_clock::now();
        }

        std::chrono::system_clock::time_point wallNow() const noexcept override
        {
            return std::chrono::system_clock::now();
        }
    };

}

#endif // CLOCK_H
