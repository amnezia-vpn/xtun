#ifndef TEST_SAMPLE_H
#define TEST_SAMPLE_H

#include <vector>

namespace libxtun::test
{
    std::vector<std::byte> sampleIpv4Packet(const char *payload = "")
    {
        size_t plen = std::strlen(payload);
        std::vector<std::byte> p(20 + plen, std::byte(0));

        p[0] = std::byte(0x45);
        p[2] = static_cast<std::byte>(p.size() >> 8);
        p[3] = static_cast<std::byte>(p.size() & 0xff);
        p[8] = std::byte(64);
        p[9] = std::byte(253);
        p[12] = std::byte(10);
        p[13] = std::byte(9);
        p[14] = std::byte(9);
        p[15] = std::byte(1);
        p[16] = std::byte(10);
        p[17] = std::byte(9);
        p[18] = std::byte(9);
        p[19] = std::byte(2);
        std::memcpy(p.data() + 20, payload, plen);
        return p;
    }
}

#endif
