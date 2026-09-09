#ifndef TEST_OS_H
#define TEST_OS_H

#include "util/noncopyable.h"

#include <cstring>
#include <optional>
#include <string>
#include <utility>

#if defined(__linux__) || defined(__APPLE__)
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <unistd.h>
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
    bool privileged()
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
#elif defined(WIN32)
            return 0;
#else
            return 0;
#endif
        }

        int m_fd = -1;
    };

    std::optional<std::pair<ScopedFd, std::string>> createTun()
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
    std::optional<bool> ifaceExists(const std::string name)
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
    int createPersistentTun(char *name, size_t len)
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

    void removePersistentTun(const char *name)
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
}

#endif
