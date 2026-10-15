#ifndef RANDOM_H
#define RANDOM_H

#include <cstdint>
#include <random>

namespace libxtun::rand
{
    namespace detail
    {
        // FIXME/TODO: it's too slow for broad usage, and per-packet
        // Consider more appropriate and faster solution here
        inline std::mt19937 &engine() noexcept
        {
            static thread_local std::mt19937 e { std::random_device {}() };
            return e;
        }
    }

    inline std::uint16_t next16() noexcept
    {
        return static_cast<std::uint16_t>(detail::engine()() & 0xffffu);
    }
    inline std::uint16_t next16(std::uint16_t lo, std::uint16_t hi) noexcept
    {
        if (hi <= lo) {
            return lo;
        }
        return std::uniform_int_distribution<std::uint16_t> { lo, hi }(detail::engine());
    }

    inline std::uint32_t next32() noexcept
    {
        return static_cast<std::uint32_t>(detail::engine()());
    }
    inline std::uint32_t next32(std::uint32_t lo, std::uint32_t hi) noexcept
    {
        if (hi <= lo) {
            return lo;
        }
        return std::uniform_int_distribution<std::uint32_t> { lo, hi }(detail::engine());
    }

    inline int nexti(int lo, int hi) noexcept
    {
        if (hi <= lo) {
            return lo;
        }
        return std::uniform_int_distribution<int> { lo, hi }(detail::engine());
    }
}

#endif // RANDOM_H
