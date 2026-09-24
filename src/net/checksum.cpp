#include "checksum.h"

namespace libxtun::net
{
    uint32_t checksumDelta(const void *bOld, const void *bNew, int len)
    {
        auto *pOld = reinterpret_cast<const uint16_t *>(bOld);
        auto *pNew = reinterpret_cast<const uint16_t *>(bNew);

        uint32_t delta = 0;
        while (len > 1) {
            delta += static_cast<uint16_t>(~(*pOld++));
            delta += *pNew++;
            len -= 2;
        }
        if (len > 0) {
            uint16_t lastOld = 0, lastNew = 0;
            *reinterpret_cast<uint8_t *>(&lastOld) = *reinterpret_cast<const uint8_t *>(pOld);
            *reinterpret_cast<uint8_t *>(&lastNew) = *reinterpret_cast<const uint8_t *>(pNew);
            delta += static_cast<uint16_t>(~lastOld);
            delta += lastNew;
        }
        return delta;
    }

    uint16_t checksumIncrement(uint16_t oldSum, uint32_t delta)
    {
        uint32_t sum = static_cast<uint16_t>(~oldSum) + delta;
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    uint16_t checksum(void *b, int len)
    {
        auto *p = reinterpret_cast<uint16_t *>(b);
        uint32_t sum = 0;

        while (len > 1) {
            sum += *p++;
            len -= 2;
        }
        if (len > 0) {
            uint16_t last = 0;
            *reinterpret_cast<uint8_t *>(last) = *reinterpret_cast<uint8_t *>(p);
            sum += last;
        }
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return static_cast<uint16_t>(~sum);
    }
}
