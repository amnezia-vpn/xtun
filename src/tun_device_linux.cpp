#include "tun_device_linux.h"
#include "xtun.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace libxtun
{
    libxtun_error LinuxTunDevice::open()
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
        }

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, "xtun", IFNAMSIZ - 1);

        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            ::close(fd);
            return LIBXTUN_ERR_DEVICE_CREATE;
        }

        m_tunFd = fd;
        m_name = ifr.ifr_name;
        return finishOpen();
    }

    libxtun_error LinuxTunDevice::adoptFd(int fd)
    {
        m_tunFd = fd;
        // FIXME(cd-amn): check if iface described by fd is up on adoption (and maybe later)
        // Note that restricted envs (e.g. Android) are NOT allowed to use monitorLoop
        m_up = true;

        // read()/write() exchange raw IP packets, so the device must have been
        // attached with IFF_TUN | IFF_NO_PI; the flags cannot be changed on an
        // already-attached descriptor.
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        if (::ioctl(fd, TUNGETIFF, &ifr) < 0 || (ifr.ifr_flags & IFF_TUN) == 0 || (ifr.ifr_flags & IFF_NO_PI) == 0) {
            return LIBXTUN_ERR_DEVICE_CREATE;
        }
        m_name = ifr.ifr_name;
        return finishOpen();
    }

    libxtun_error LinuxTunDevice::adoptName(const char *name)
    {
        if (std::strlen(name) >= IFNAMSIZ) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        // TUNSETIFF creates a fresh device when the name is free, so adoption
        // must first check that the interface already exists.
        int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock < 0) {
            return LIBXTUN_ERR_SYSTEM;
        }

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            ::close(sock);
            return LIBXTUN_ERR_DEVICE_CREATE;
        }
        ::close(sock);

        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
        }

        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            ::close(fd);
            return LIBXTUN_ERR_DEVICE_CREATE;
        }

        m_tunFd = fd;
        m_name = ifr.ifr_name;
        return finishOpen();
    }

    int LinuxTunDevice::read(std::span<std::byte> buf) noexcept
    {
        if (m_tunFd < 0) {
            return IO_FATAL;
        }

        struct pollfd fds[2];
        fds[0].fd = m_tunFd;
        fds[0].events = POLLIN;
        fds[1].fd = m_readCancelFd;
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
                while (::read(m_readCancelFd, &drained, sizeof(drained)) > 0) {
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

        return static_cast<int>(::read(m_tunFd, buf.data(), buf.size()));
    }

    int LinuxTunDevice::write(std::span<const std::byte> buf) noexcept
    {
        return static_cast<int>(::write(m_tunFd, buf.data(), buf.size()));
    }

    int LinuxTunDevice::mtu() const noexcept
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

    const std::string &LinuxTunDevice::name() const noexcept
    {
        return m_name;
    }

    int LinuxTunDevice::ifIndex() const noexcept
    {
        return m_ifIndex;
    }

    bool LinuxTunDevice::up() const noexcept
    {
        return m_up.load();
    }

    void LinuxTunDevice::resetReadCancellation() noexcept
    {
        m_readCancelled.store(false, std::memory_order_release);
        m_injectPending.store(false, std::memory_order_release);

        if (m_readCancelFd < 0) {
            return;
        }

        uint64_t drained;
        while (::read(m_readCancelFd, &drained, sizeof(drained)) > 0) {
        }
    }

    void LinuxTunDevice::wakeRead() noexcept
    {
        m_injectPending.store(true, std::memory_order_release);
        if (m_readCancelFd >= 0) {
            uint64_t one = 1;
            (void)::write(m_readCancelFd, &one, sizeof(one));
        }
    }

    void LinuxTunDevice::cancelRead() noexcept
    {
        m_readCancelled.store(true, std::memory_order_release);
        if (m_readCancelFd >= 0) {
            uint64_t one = 1;
            (void)::write(m_readCancelFd, &one, sizeof(one));
        }
    }

    void LinuxTunDevice::startMonitor(TunDeviceListener &listener)
    {
        m_listener = &listener;
        m_mtu = mtu();

        m_monitorFd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (m_monitorFd < 0) {
            m_listener = nullptr;
            return;
        }

        struct sockaddr_nl addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = RTMGRP_LINK;
        if (::bind(m_monitorFd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
            ::close(m_monitorFd);
            m_monitorFd = -1;
            m_listener = nullptr;
            return;
        }

        m_monitorCancelFd = ::eventfd(0, EFD_CLOEXEC);
        if (m_monitorCancelFd < 0) {
            ::close(m_monitorFd);
            m_monitorFd = -1;
            m_listener = nullptr;
            return;
        }

        m_monitor = std::thread(&LinuxTunDevice::monitorLoop, this);
    }

    void LinuxTunDevice::stopMonitor() noexcept
    {
        if (m_monitor.joinable()) {
            uint64_t one = 1;
            (void)::write(m_monitorCancelFd, &one, sizeof(one));
            m_monitor.join();
        }
        if (m_monitorFd >= 0) {
            ::close(m_monitorFd);
            m_monitorFd = -1;
        }
        if (m_monitorCancelFd >= 0) {
            ::close(m_monitorCancelFd);
            m_monitorCancelFd = -1;
        }
        m_listener = nullptr;
    }

    LinuxTunDevice::~LinuxTunDevice()
    {
        stopMonitor();
        cancelRead();
        closeTun();

        if (m_readCancelFd >= 0) {
            ::close(m_readCancelFd);
        }
    }

    libxtun_error LinuxTunDevice::finishOpen()
    {
        // SIOCGIFINDEX is a socket ioctl, not a tun-device one, so it must go
        // through an AF_INET socket rather than the tun fd. The interface is
        // selected by name (ifr_name), not by the socket.
        int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock < 0) {
            closeTun();
            return LIBXTUN_ERR_SYSTEM;
        }

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);
        if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            ::close(sock);
            closeTun();
            return LIBXTUN_ERR_SYSTEM;
        }
        ::close(sock);
        m_ifIndex = ifr.ifr_ifindex;

        m_readCancelFd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (m_readCancelFd < 0) {
            closeTun();
            return LIBXTUN_ERR_SYSTEM;
        }

        return LIBXTUN_OK;
    }

    void LinuxTunDevice::closeTun() noexcept
    {
        if (m_tunFd >= 0) {
            ::close(m_tunFd);
            m_tunFd = -1;
        }
    }

    void LinuxTunDevice::monitorLoop() noexcept
    {
        struct pollfd fds[2];
        fds[0].fd = m_monitorFd;
        fds[0].events = POLLIN;
        fds[1].fd = m_monitorCancelFd;
        fds[1].events = POLLIN;

        alignas(4) char buf[8192];

        for (;;) {
            if (::poll(fds, 2, -1) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }

            if (fds[1].revents & POLLIN) {
                break;
            }
            if (!(fds[0].revents & POLLIN)) {
                continue;
            }

            int len = static_cast<int>(::recv(m_monitorFd, buf, sizeof(buf), 0));
            if (len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }

            for (struct nlmsghdr *nh = reinterpret_cast<struct nlmsghdr *>(buf); NLMSG_OK(nh, len);
                 nh = NLMSG_NEXT(nh, len)) {
                if (nh->nlmsg_type != RTM_NEWLINK) {
                    continue;
                }

                struct ifinfomsg *ifi = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nh));
                if (ifi->ifi_index != m_ifIndex) {
                    continue;
                }

                bool nowUp = (ifi->ifi_flags & IFF_RUNNING) != 0;
                if (nowUp != m_up.exchange(nowUp) && m_listener != nullptr) {
                    m_listener->onLinkStateChanged(nowUp);
                }

                int rtaLen = static_cast<int>(IFLA_PAYLOAD(nh));
                for (struct rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, rtaLen); rta = RTA_NEXT(rta, rtaLen)) {
                    if (rta->rta_type != IFLA_MTU) {
                        continue;
                    }
                    int newMtu = *reinterpret_cast<int *>(RTA_DATA(rta));
                    if (newMtu != m_mtu.exchange(newMtu) && m_listener != nullptr) {
                        m_listener->onMtuChanged(newMtu);
                    }
                }
            }
        }
    }
}
