#ifndef TUNNEL_IO_H
#define TUNNEL_IO_H

#include "net/ip.h"
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

        virtual int read(std::span<std::byte> buf) = 0;
        virtual int write(std::span<const std::byte> packet) = 0;
        virtual void protectSocket(int fd) = 0;
        virtual void halt() = 0;

        virtual int mtu() const = 0;
        virtual std::vector<net::IpPrefix> addresses() = 0;
    };
}

#endif // TUNNEL_IO_H
