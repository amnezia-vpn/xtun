#ifndef NET_NETWORK_ORDER_H
#define NET_NETWORK_ORDER_H

#include "net/sys.h" // IWYU pragma: keep

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <span>

namespace libxtun::net
{
    template<typename C>
    concept ByteOutput = std::ranges::contiguous_range<C> && std::same_as<std::ranges::range_value_t<C>, std::byte>
            && requires(C &out, std::byte b) { out.push_back(b); };

    void appendBigEndian16(ByteOutput auto &out, std::uint16_t value)
    {
        const std::uint16_t raw = htons(value);
        std::array<std::byte, sizeof(raw)> octets {};
        std::memcpy(octets.data(), &raw, sizeof(raw));
        for (std::byte b : octets) {
            out.push_back(b);
        }
    }

    void appendBigEndian32(ByteOutput auto &out, std::uint32_t value)
    {
        const std::uint32_t raw = htonl(value);
        std::array<std::byte, sizeof(raw)> octets {};
        std::memcpy(octets.data(), &raw, sizeof(raw));
        for (std::byte b : octets) {
            out.push_back(b);
        }
    }

    inline std::uint16_t readBigEndian16(std::span<const std::byte> data, std::size_t offset) noexcept
    {
        if (offset + sizeof(std::uint16_t) > data.size()) {
            return 0;
        }
        std::uint16_t raw = 0;
        std::memcpy(&raw, data.data() + offset, sizeof(raw));
        return ntohs(raw);
    }

    inline void writeBigEndian16(std::span<std::byte> out, std::size_t offset, std::uint16_t value) noexcept
    {
        if (offset + sizeof(value) > out.size()) {
            return;
        }
        const std::uint16_t raw = htons(value);
        std::memcpy(out.data() + offset, &raw, sizeof(raw));
    }
}

#endif // NET_NETWORK_ORDER_H
