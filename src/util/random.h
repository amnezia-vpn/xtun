#ifndef RANDOM_H
#define RANDOM_H

#include <cstdint>
#include <random>

namespace libxtun {

class RandomSource {
  public:
    RandomSource() : m_engine(std::random_device{}()) {}
    explicit RandomSource(std::uint32_t seed) noexcept : m_engine(seed) {}

    std::uint16_t next16() noexcept { return static_cast<std::uint16_t>(m_engine() & 0xffffu); }

    std::uint32_t next32() noexcept { return static_cast<std::uint32_t>(m_engine()); }

    int inRange(int lo, int hi) noexcept {
        if (hi <= lo) {
            return lo;
        }
        const std::uint32_t span = static_cast<std::uint32_t>(hi - lo) + 1u;
        return lo + static_cast<int>(next32() % span);
    }

  private:
    std::mt19937 m_engine;
};

}

#endif // RANDOM_H
