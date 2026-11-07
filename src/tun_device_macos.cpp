#include <TargetConditionals.h>

#include "tun_device_macos.h"
#include "xtun.h"

#include <cerrno>
#include <cstdint>
#include <cstring>

#include <fcntl.h>
#include <net/if.h>
#if TARGET_OS_OSX
    #include <net/if_utun.h>
    #include <net/route.h>
    #include <sys/kern_control.h>
    #include <sys/sys_domain.h>
#endif
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/uio.h>
#include <unistd.h>

namespace libxtun
{
    libxtun_error MacosTunDevice::open()
    {
#if TARGET_OS_OSX
        int fd = ::socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
        }

        // Resolve the utun kernel control and connect to it. sc_unit == 0 asks the
        // kernel to assign the next free utun unit (utunN).
        struct ctl_info ctlInfo;
        std::memset(&ctlInfo, 0, sizeof(ctlInfo));
        std::strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name) - 1);
        if (::ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
            ::close(fd);
            return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
        }

        struct sockaddr_ctl sc;
        std::memset(&sc, 0, sizeof(sc));
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_id = ctlInfo.ctl_id;
        sc.sc_unit = 0;

        if (::connect(fd, reinterpret_cast<struct sockaddr *>(&sc), sizeof(sc)) < 0) {
            ::close(fd);
            return LIBXTUN_ERR_DEVICE_CREATE;
        }
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);

        m_tunFd = fd;

        // The kernel picks the name (utunN); read it back off the control socket.
        char ifname[IFNAMSIZ];
        socklen_t ifnameLen = sizeof(ifname);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifnameLen) < 0) {
            closeTun();
            return LIBXTUN_ERR_SYSTEM;
        }
        m_name = ifname;

        return finishOpen();
#endif
        return LIBXTUN_ERR_UNSUPPORTED;
    }

    libxtun_error MacosTunDevice::adoptFd(int fd)
    {
        m_tunFd = fd;
        m_up = true;

#if TARGET_OS_OSX
        char ifname[IFNAMSIZ];
        socklen_t ifnameLen = sizeof(ifname);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifnameLen) < 0) {
            return LIBXTUN_ERR_DEVICE_CREATE;
        }
        m_name = ifname;
#endif

        return finishOpen();
    }

    libxtun_error MacosTunDevice::adoptName(const char *name)
    {
        (void)name;
        return LIBXTUN_ERR_UNSUPPORTED;
    }

    int MacosTunDevice::read(std::span<std::byte> buf) noexcept
    {
        if (m_tunFd < 0) {
            return IO_FATAL;
        }

        struct pollfd fds[2];
        fds[0].fd = m_tunFd;
        fds[0].events = POLLIN;
        fds[1].fd = m_readCancelRd;
        fds[1].events = POLLIN;

        for (;;) {
            if (m_readCancelled.load(std::memory_order_acquire)) {
                return IO_FATAL;
            }
            if (::poll(fds, 2, -1) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return IO_FATAL;
            }
            if (fds[1].revents & POLLIN) {
                uint64_t drained;
                while (::read(m_readCancelRd, &drained, sizeof(drained)) > 0) {
                }
                if (m_readCancelled.load(std::memory_order_acquire)) {
                    return IO_FATAL;
                }
                if (m_injectPending.exchange(false, std::memory_order_acquire)) {
                    return READ_WAKE;
                }
                continue;
            }
            if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
                break;
            }
        }

        // utun prepends a 4-byte address-family header; strip it with a scatter
        // read so callers still deal in raw IP packets.
        unsigned char hdr[4];
        struct iovec iov[2];
        iov[0].iov_base = hdr;
        iov[0].iov_len = sizeof(hdr);
        iov[1].iov_base = buf.data();
        iov[1].iov_len = buf.size();

        ssize_t n = ::readv(m_tunFd, iov, 2);
        if (n < static_cast<ssize_t>(sizeof(hdr))) {
            return IO_FATAL;
        }
        return static_cast<int>(n - sizeof(hdr));
    }

    int MacosTunDevice::write(std::span<const std::byte> buf) noexcept
    {
        // utun expects a 4-byte address-family header; prepend it with a scatter
        // write, deriving the family from the IP version nibble.
        if (buf.empty()) {
            return -1;
        }
        unsigned char version = static_cast<unsigned char>(buf[0]) >> 4;
        unsigned char af;
        if (version == 4) {
            af = AF_INET;
        } else if (version == 6) {
            af = AF_INET6;
        } else {
            return -1;
        }

        unsigned char hdr[4] = { 0, 0, 0, af };
        struct iovec iov[2];
        iov[0].iov_base = hdr;
        iov[0].iov_len = sizeof(hdr);
        iov[1].iov_base = const_cast<std::byte *>(buf.data());
        iov[1].iov_len = buf.size();

        ssize_t n = ::writev(m_tunFd, iov, 2);
        if (n < static_cast<ssize_t>(sizeof(hdr))) {
            return -1;
        }
        return static_cast<int>(n - sizeof(hdr));
    }

    int MacosTunDevice::mtu() const noexcept
    {
        int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return -1;
        }
        ::fcntl(sock, F_SETFD, FD_CLOEXEC);

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);

        int result = -1;
        if (::ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
            result = ifr.ifr_mtu;
        }

        ::close(sock);
        return result;
    }

    const std::string &MacosTunDevice::name() const noexcept
    {
        return m_name;
    }

    int MacosTunDevice::ifIndex() const noexcept
    {
        return m_ifIndex;
    }

    bool MacosTunDevice::up() const noexcept
    {
        return m_up.load();
    }

    void MacosTunDevice::resetReadCancellation() noexcept
    {
        m_readCancelled.store(false, std::memory_order_release);
        m_injectPending.store(false, std::memory_order_release);

        if (m_readCancelRd < 0) {
            return;
        }

        uint64_t drained;
        while (::read(m_readCancelRd, &drained, sizeof(drained)) > 0) {
        }
    }

    void MacosTunDevice::wakeRead() noexcept
    {
        m_injectPending.store(true, std::memory_order_release);
        if (m_readCancelWr >= 0) {
            uint64_t one = 1;
            (void)::write(m_readCancelWr, &one, sizeof(one));
        }
    }

    void MacosTunDevice::cancelRead() noexcept
    {
        m_readCancelled.store(true, std::memory_order_release);
        if (m_readCancelWr >= 0) {
            uint64_t one = 1;
            (void)::write(m_readCancelWr, &one, sizeof(one));
        }
    }

    void MacosTunDevice::startMonitor(TunDeviceListener &listener)
    {
        m_listener = &listener;
        m_mtu = mtu();

        m_monitorFd = ::socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC);
        if (m_monitorFd < 0) {
            m_listener = nullptr;
            return;
        }
        ::fcntl(m_monitorFd, F_SETFD, FD_CLOEXEC);

        m_monitor = std::thread(&MacosTunDevice::monitorLoop, this);
    }

    void MacosTunDevice::stopMonitor() noexcept
    {
        // Route sockets have no eventfd equivalent; shutting the socket down
        // unblocks the monitor thread's read() so it can exit.
        if (m_monitor.joinable()) {
            ::shutdown(m_monitorFd, SHUT_RDWR);
            m_monitor.join();
        }
        if (m_monitorFd >= 0) {
            ::close(m_monitorFd);
            m_monitorFd = -1;
        }
        m_listener = nullptr;
    }

    MacosTunDevice::~MacosTunDevice()
    {
        stopMonitor();
        cancelRead();
        closeTun();

        if (m_readCancelRd >= 0) {
            ::close(m_readCancelRd);
        }
        if (m_readCancelWr >= 0) {
            ::close(m_readCancelWr);
        }
    }

    libxtun_error MacosTunDevice::finishOpen()
    {
#if TARGET_OS_OSX
        m_ifIndex = static_cast<int>(::if_nametoindex(m_name.c_str()));
        if (m_ifIndex == 0) {
            closeTun();
            return LIBXTUN_ERR_SYSTEM;
        }
#endif

        int cancelPipe[2];
        if (::pipe(cancelPipe) < 0) {
            closeTun();
            return LIBXTUN_ERR_SYSTEM;
        }
        ::fcntl(cancelPipe[0], F_SETFD, FD_CLOEXEC);
        ::fcntl(cancelPipe[1], F_SETFD, FD_CLOEXEC);
        ::fcntl(cancelPipe[0], F_SETFL, O_NONBLOCK);
        m_readCancelRd = cancelPipe[0];
        m_readCancelWr = cancelPipe[1];

        return LIBXTUN_OK;
    }

    void MacosTunDevice::closeTun() noexcept
    {
        if (m_tunFd >= 0) {
            ::close(m_tunFd);
            m_tunFd = -1;
        }
    }

    void MacosTunDevice::monitorLoop() noexcept
    {
#if TARGET_OS_OSX
        alignas(4) char buf[4096];

        for (;;) {
            ssize_t n = ::read(m_monitorFd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (n == 0) {
                break;
            }
            if (n < static_cast<ssize_t>(sizeof(struct rt_msghdr))) {
                continue;
            }

            struct rt_msghdr *rtm = reinterpret_cast<struct rt_msghdr *>(buf);
            switch (rtm->rtm_type) {
            case RTM_ADD:
            case RTM_DELETE:
            case RTM_CHANGE:
                if (rtm->rtm_index == m_ifIndex) {
                    bool nowUp = (rtm->rtm_flags & RTF_UP) != 0;
                    if (nowUp != m_up.exchange(nowUp) && m_listener != nullptr) {
                        m_listener->onLinkStateChanged(nowUp);
                    }
                    if (m_listener != nullptr) {
                        m_listener->onRouteChanged();
                    }
                } else if ((rtm->rtm_flags & RTF_GATEWAY) && !(rtm->rtm_flags & RTF_IFSCOPE)) {
                    if (m_listener != nullptr) {
                        m_listener->onRouteChanged();
                    }
                }
                break;
            case RTM_IFINFO:
                if (n >= static_cast<ssize_t>(sizeof(struct if_msghdr))) {
                    struct if_msghdr *ifm = reinterpret_cast<struct if_msghdr *>(buf);
                    if (ifm->ifm_index != m_ifIndex) {
                        break;
                    }

                    bool nowUp = (ifm->ifm_flags & IFF_UP) != 0;
                    if (nowUp != m_up.exchange(nowUp) && m_listener != nullptr) {
                        m_listener->onLinkStateChanged(nowUp);
                    }

                    int newMtu = static_cast<int>(ifm->ifm_data.ifi_mtu);
                    if (newMtu != m_mtu.exchange(newMtu) && m_listener != nullptr) {
                        m_listener->onMtuChanged(newMtu);
                    }
                }
                break;
            default: break;
            }
        }
#endif
    }
}
