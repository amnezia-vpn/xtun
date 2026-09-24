#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <cstdint>

namespace libxtun::net
{
    uint16_t checksum(void *b, int len);

    // RFC 1624: Checksum incremental update
    uint32_t checksumDelta(const void *bOld, const void *bNew, int len);
    uint16_t checksumIncrement(uint16_t oldSum, uint32_t delta);
}

#endif
