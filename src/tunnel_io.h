#ifndef TUNNEL_IO_H
#define TUNNEL_IO_H

#include <cstddef>
#include <span>

namespace libxtun
{
    inline constexpr int READ_WAKE = 0;
    inline constexpr int IO_FATAL = -1;

    class TunnelIo
    {
    public:
        virtual ~TunnelIo() = default;

        virtual int read(std::span<std::byte> buf) noexcept = 0;
        virtual int write(std::span<const std::byte> packet) noexcept = 0;
        virtual int mtu() const noexcept = 0;
        virtual void protectSocket(int fd) noexcept = 0;
    };
}

#endif // TUNNEL_IO_H
