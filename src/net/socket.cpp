#include "socket.h"

#include <utility>

#if !defined(_WIN32)
    #include <fcntl.h>
#endif

namespace libxtun::net
{
    namespace
    {

#if defined(_WIN32)
        bool winsockReady() noexcept
        {
            static const bool ready = [] {
                WSADATA data {};
                return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
            }();
            return ready;
        }
#endif
    }

#if defined(_WIN32)
    int toAbiDescriptor(SOCKET handle) noexcept
    {
        return static_cast<int>(handle);
    }

    SOCKET fromAbiDescriptor(int fd) noexcept
    {
        return static_cast<SOCKET>(fd);
    }

#endif

    Socket::Socket(Socket &&other) noexcept : m_handle(other.m_handle)
    {
#if defined(_WIN32)
        other.m_handle = INVALID_SOCKET;
#else
        other.m_handle = -1;
#endif
    }

    Socket &Socket::operator=(Socket &&other) noexcept
    {
        if (this != &other) {
            close();
            m_handle = other.m_handle;
#if defined(_WIN32)
            other.m_handle = INVALID_SOCKET;
#else
            other.m_handle = -1;
#endif
        }
        return *this;
    }

    Socket::~Socket()
    {
        close();
    }

    std::optional<Socket> Socket::udp(int family)
    {
#if defined(_WIN32)
        if (!winsockReady()) {
            return std::nullopt;
        }
        const SOCKET handle = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
        if (handle == INVALID_SOCKET) {
            return std::nullopt;
        }
#elif defined(__linux__)
        const int handle = ::socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (handle < 0) {
            return std::nullopt;
        }
#else
        const int handle = ::socket(family, SOCK_DGRAM, 0);
        if (handle < 0) {
            return std::nullopt;
        }
        ::fcntl(handle, F_SETFD, FD_CLOEXEC);
#endif

        Socket socket;
        socket.m_handle = handle;
        return socket;
    }

    int Socket::native() const noexcept
    {
        return toAbiDescriptor(m_handle);
    }

    bool Socket::connect(const SockAddr &peer)
    {
        return ::connect(m_handle, peer.data(), peer.size()) == 0;
    }

    bool Socket::send(std::span<const std::byte> data)
    {
#if defined(_WIN32)
        const int n = ::send(m_handle, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0);
        return n == static_cast<int>(data.size());
#else
        const ssize_t n = ::send(m_handle, data.data(), data.size(), 0);
        return n == static_cast<ssize_t>(data.size());
#endif
    }

    std::optional<std::size_t> Socket::receive(std::span<std::byte> buf)
    {
#if defined(_WIN32)
        const int n = ::recv(m_handle, reinterpret_cast<char *>(buf.data()), static_cast<int>(buf.size()), 0);
#else
        const ssize_t n = ::recv(m_handle, buf.data(), buf.size(), 0);
#endif
        if (n < 0) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(n);
    }

    bool Socket::waitReadable(std::chrono::milliseconds timeout)
    {
#if defined(_WIN32)
        WSAPOLLFD fd {};
        fd.fd = m_handle;
        fd.events = POLLRDNORM;
        return ::WSAPoll(&fd, 1, static_cast<int>(timeout.count())) > 0 && (fd.revents & POLLRDNORM) != 0;
#else
        pollfd fd {};
        fd.fd = m_handle;
        fd.events = POLLIN;
        return ::poll(&fd, 1, static_cast<int>(timeout.count())) > 0 && (fd.revents & POLLIN) != 0;
#endif
    }

    void Socket::close() noexcept
    {
#if defined(_WIN32)
        if (m_handle != INVALID_SOCKET) {
            ::closesocket(m_handle);
            m_handle = INVALID_SOCKET;
        }
#else
        if (m_handle >= 0) {
            ::close(m_handle);
            m_handle = -1;
        }
#endif
    }
}
