#include "checksum.h"
#include <cstring>

namespace
{
    uint16_t load16(const void *p)
    {
        uint16_t val;
        std::memcpy(&val, p, 2);
        return val;
    }
}

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

    void Checksum::update(std::span<const std::byte> s)
    {
        update(s.data(), s.size());
    }

    void Checksum::update(const void *data, std::size_t n)
    {
        auto *p = reinterpret_cast<const uint8_t *>(data);
        if (m_hasOdd && n > 0) {
            uint8_t pair[2] = { m_odd, *p++ };
            m_sum += load16(pair);
            --n;
            m_hasOdd = false;
        }
        while (n > 1) {
            m_sum += load16(p);
            p += 2;
            n -= 2;
        }
        if (n > 0) {
            m_odd = *p;
            m_hasOdd = true;
        }
    }

    uint16_t Checksum::finalize()
    {
        uint32_t sum = m_sum;
        if (m_hasOdd) {
            uint8_t pair[2] = { m_odd, 0 };
            sum += load16(pair);
        }
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return static_cast<uint16_t>(~sum);
    }

    void Checksum::reset()
    {
        m_sum = 0;
        m_hasOdd = false;
    }
}
