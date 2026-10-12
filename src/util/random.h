#ifndef RANDOM_H
#define RANDOM_H

#include <cstdint>
#include <random>

namespace
{
    static std::mt19937 &engine() noexcept
    {
        static thread_local std::mt19937 e { std::random_device {}() };
        return e;
    }
}

namespace libxtun::rand
{
    static std::uint16_t next16() noexcept
    {
        return static_cast<std::uint16_t>(engine()() & 0xffffu);
    }
    static std::uint16_t next16(std::uint16_t lo, std::uint16_t hi) noexcept
    {
        if (hi <= lo) {
            return lo;
        }
        return std::uniform_int_distribution<std::uint16_t> { lo, hi }(engine());
    }

    static std::uint32_t next32() noexcept
    {
        return static_cast<std::uint32_t>(engine()());
    }
    static std::uint32_t next32(std::uint32_t lo, std::uint32_t hi) noexcept
    {
        if (hi <= lo) {
            return lo;
        }
        return std::uniform_int_distribution<std::uint32_t> { lo, hi }(engine());
    }

    static int nexti(int lo, int hi) noexcept
    {
        if (hi <= lo) {
            return lo;
        }
        return std::uniform_int_distribution<int> { lo, hi }(engine());
    }
}

#endif // RANDOM_H
