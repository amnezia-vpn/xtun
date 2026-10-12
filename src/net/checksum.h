#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <cstddef>
#include <cstdint>
#include <span>

namespace libxtun::net
{
    // RFC 1624: Checksum incremental update
    uint32_t checksumDelta(const void *bOld, const void *bNew, int len);
    uint16_t checksumIncrement(uint16_t oldSum, uint32_t delta);

    class Checksum
    {
    public:
        void update(std::span<const std::byte> s);
        void update(const void *p, std::size_t n);
        uint16_t finalize();
        void reset();

    private:
        uint32_t m_sum = 0;
        bool m_hasOdd = 0;
        uint8_t m_odd;
    };
}

#endif
