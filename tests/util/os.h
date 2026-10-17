#ifndef TEST_OS_H
#define TEST_OS_H

#include "util/noncopyable.h"

#include <cerrno>
#include <chrono>
#include <optional>
#include <string>
#include <utility>

#if defined(__linux__) || defined(__APPLE__)
    #include <arpa/inet.h>
    #include <cstring>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#ifdef _WIN32
    #include <winsock2.h>
    #define poll WSAPoll
#else
    #include <sys/poll.h>
#endif

#if defined(__linux__)
    #include <linux/if.h>
    #include <linux/if_tun.h>
#endif

#if defined(__APPLE__)
    #include <net/if.h>
    #include <net/if_utun.h>
    #include <sys/kern_control.h>
    #include <sys/sys_domain.h>
#endif

#if defined(_WIN32)
    #include <iphlpapi.h>
    #include <windows.h>
    #include <winsock2.h>
    #include <wintun.h>
    #include <ws2tcpip.h>
#endif

namespace libxtun::test
{
    static bool privileged()
    {
#if defined(__linux__) || defined(__APPLE__)
        return ::geteuid() == 0;
#elif defined(_WIN32)
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (::AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0,
                                       0, 0, 0, &adminGroup)) {
            ::CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            ::FreeSid(adminGroup);
        }
        return isAdmin != FALSE;
#endif
    }

    class ScopedFd : private NonCopyable
    {
    public:
        ScopedFd() = default;
        explicit ScopedFd(int fd) : m_fd(fd)
        {
        }
        ScopedFd(ScopedFd &&other) noexcept : m_fd(std::exchange(other.m_fd, -1))
        {
        }
        ScopedFd &operator=(ScopedFd &&other) noexcept
        {
            if (this != &other) {
                if (m_fd >= 0)
                    close(m_fd);
                m_fd = std::exchange(other.m_fd, -1);
            }
            return *this;
        }
        ~ScopedFd()
        {
            if (m_fd >= 0)
                close(m_fd);
        }

        explicit operator bool() const
        {
            return m_fd >= 0;
        }
        int get() const
        {
            return m_fd;
        }
        int release()
        {
            return std::exchange(m_fd, -1);
        }

    private:
        static int close(int fd)
        {
#if defined(__linux__) || defined(__APPLE__)
            return ::close(fd);
#elif defined(_WIN32)
            return ::closesocket(static_cast<SOCKET>(fd));
#else
            return 0;
#endif
        }

        int m_fd = -1;
    };

    static std::optional<std::pair<ScopedFd, std::string>> createTun()
    {
#if defined(__linux__)
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return std::make_pair(ScopedFd(), "");
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            ::close(fd);
            return std::make_pair(ScopedFd(), "");
        }
        return std::make_pair(ScopedFd(fd), ifr.ifr_name);
#elif defined(__APPLE__)
        static char name[IFNAMSIZ];
        int fd = ::socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            return std::make_pair(ScopedFd(), "");
        }
        struct ctl_info info;
        std::memset(&info, 0, sizeof(info));
        std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
        if (::ioctl(fd, CTLIOCGINFO, &info) < 0) {
            ::close(fd);
            return std::make_pair(ScopedFd(), "");
        }
        struct sockaddr_ctl sc;
        std::memset(&sc, 0, sizeof(sc));
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_id = info.ctl_id;
        sc.sc_unit = 0;
        if (::connect(fd, reinterpret_cast<struct sockaddr *>(&sc), sizeof(sc)) < 0) {
            ::close(fd);
            return std::make_pair(ScopedFd(), "");
        }
        socklen_t len = IFNAMSIZ;
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len) < 0) {
            ::close(fd);
            return std::make_pair(ScopedFd(), "");
        }
        return std::make_pair(ScopedFd(fd), name);
#else
        return {};
#endif
    }

    // Independent of libxtun: ask the kernel directly whether the interface exists.
    static std::optional<bool> ifaceExists(const std::string name)
    {
#if defined(__linux__)
        int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock < 0) {
            return false;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        bool exists = ::ioctl(sock, SIOCGIFINDEX, &ifr) == 0;
        ::close(sock);
        return exists;
#else
        return {};
#endif
    }

#if defined(__linux__)
    static int createPersistentTun(char *name, size_t len)
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (::ioctl(fd, TUNSETIFF, &ifr) < 0 || ::ioctl(fd, TUNSETPERSIST, 1) < 0) {
            ::close(fd);
            return -1;
        }
        ::close(fd);
        std::snprintf(name, len, "%s", ifr.ifr_name);
        return 0;
    }

    static void removePersistentTun(const char *name)
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        if (::ioctl(fd, TUNSETIFF, &ifr) == 0) {
            ::ioctl(fd, TUNSETPERSIST, 0);
        }
        ::close(fd);
    }
#endif

    static int udpOpen(std::string host, uint16_t port)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            return sock;
        }

        if (int res = connect(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)); res < 0) {
            return res;
        }

        return sock;
    }

    static int lastSocketError()
    {
#if defined(_WIN32)
        return ::WSAGetLastError();
#else
        return errno;
#endif
    }

    struct ConnectedSocket
    {
        ScopedFd fd;
        int error = 0;
    };

    static ConnectedSocket connectSocket(const std::string &host, uint16_t port, int type, [[maybe_unused]] unsigned mark)
    {
        ::addrinfo hints {};
        hints.ai_socktype = type;
        hints.ai_protocol = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

        ::addrinfo *ptr = nullptr;
        if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ptr) != 0) {
            return { {}, EINVAL };
        }
        std::unique_ptr<::addrinfo, decltype(&::freeaddrinfo)> resolved(ptr, &::freeaddrinfo);

        ScopedFd sock(static_cast<int>(::socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol)));
        if (!sock) {
            return { {}, lastSocketError() };
        }
#if defined(__linux__)
        if (mark != 0 && ::setsockopt(sock.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
            return { {}, lastSocketError() };
        }
#endif
#if defined(_WIN32)
        u_long nonBlocking = 1;
        if (type == SOCK_STREAM && ::ioctlsocket(static_cast<SOCKET>(sock.get()), FIONBIO, &nonBlocking) != 0) {
            return { {}, lastSocketError() };
        }
#else
        if (type == SOCK_STREAM && ::fcntl(sock.get(), F_SETFL, ::fcntl(sock.get(), F_GETFL) | O_NONBLOCK) != 0) {
            return { {}, lastSocketError() };
        }
#endif
        if (::connect(sock.get(), resolved->ai_addr, static_cast<int>(resolved->ai_addrlen)) != 0) {
            return { std::move(sock), lastSocketError() };
        }

        return { std::move(sock), 0 };
    }

    static ConnectedSocket udpConnect(const std::string &host, uint16_t port, unsigned mark = 0)
    {
        return connectSocket(host, port, SOCK_DGRAM, mark);
    }

#ifdef _WIN32
    constexpr int ERR_IN_PROGRESS = WSAEWOULDBLOCK;
    constexpr int ERR_INTERRUPTED = WSAEINTR;
#else
    constexpr int ERR_IN_PROGRESS = EINPROGRESS;
    constexpr int ERR_INTERRUPTED = EINTR;
#endif

    static ConnectedSocket tcpConnect(const std::string &host, uint16_t port,
                                      std::chrono::milliseconds timeout = std::chrono::milliseconds(100))
    {
        auto [sock, err] = connectSocket(host, port, SOCK_STREAM, 0);
        if (err != ERR_IN_PROGRESS && err != ERR_INTERRUPTED) {
            return { std::move(sock), err };
        }
#ifdef _WIN32
        SOCKET fd = static_cast<SOCKET>(sock.get());
#else
        int fd = sock.get();
#endif

        ::pollfd pfd { fd, POLLOUT, 0 };
        auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (left.count() <= 0) {
                return { {}, ETIMEDOUT };
            }

            int n = ::poll(&pfd, 1, static_cast<int>(left.count()));
            if (n > 0) {
                break;
            }
            if (n == 0) {
                return { {}, ETIMEDOUT };
            }
            if (int err = lastSocketError(); err != ERR_INTERRUPTED) {
                return { {}, err };
            }
        }

        int sockErr = 0;
        ::socklen_t len = sizeof(sockErr);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&sockErr), &len) != 0) {
            return { {}, lastSocketError() };
        }
        return { std::move(sock), sockErr };
    }

    static std::vector<std::string> resolve(const std::string &host)
    {
#if defined(_WIN32)
        static const bool wsaInit = [] {
            WSADATA wsa;
            return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
        }();
#endif
        ::addrinfo hints {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        ::addrinfo *ptr = nullptr;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &ptr) != 0) {
            return {};
        }
        std::unique_ptr<::addrinfo, decltype(&::freeaddrinfo)> resolved(ptr, &::freeaddrinfo);

        std::vector<std::string> res;
        for (auto *it = resolved.get(); it; it = it->ai_next) {
            char buf[INET_ADDRSTRLEN] {};
            auto *sin = reinterpret_cast<const sockaddr_in *>(it->ai_addr);
            if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
                res.emplace_back(buf);
            }
        }
        return res;
    }
}

#endif
