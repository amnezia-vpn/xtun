#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include "net/ip.h"
#include "net/sys.h"
#include "util/noncopyable.h"

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>

namespace libxtun::net
{

#if defined(_WIN32)
    int toAbiDescriptor(SOCKET handle) noexcept;
    SOCKET fromAbiDescriptor(int fd) noexcept;
#else
    inline int toAbiDescriptor(int fd) noexcept
    {
        return fd;
    }
    inline int fromAbiDescriptor(int fd) noexcept
    {
        return fd;
    }
#endif

    class Socket : private NonCopyable
    {
    public:
        Socket(Socket &&other) noexcept;
        Socket &operator=(Socket &&other) noexcept;
        ~Socket();

        static std::optional<Socket> udp(int family);
        int native() const noexcept;
        [[nodiscard]] bool connect(const SockAddr &peer);
        [[nodiscard]] bool send(std::span<const std::byte> data);
        [[nodiscard]] std::optional<std::size_t> receive(std::span<std::byte> buf);
        [[nodiscard]] bool waitReadable(std::chrono::milliseconds timeout);

    private:
        Socket() = default;

        void close() noexcept;

#if defined(_WIN32)
        SOCKET m_handle = INVALID_SOCKET;
#else
        int m_handle = -1;
#endif
    };

}

#endif // NET_SOCKET_H
