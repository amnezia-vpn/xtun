#include "tunnel.h"

#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#endif

namespace {

std::vector<std::string> parseStrList(const libxtun_str_list &l) {
    std::vector<std::string> out;
    if (l.list == nullptr) {
        return out;
    }
    out.reserve(l.size);
    const char *p = l.list;
    for (size_t i = 0; i < l.size; ++i) {
        out.emplace_back(p);
        p += out.back().size() + 1;
    }
    return out;
}

}

namespace libxtun {

Tunnel::Tunnel(const libxtun_tunnel_opts &opts)
    : m_dns(parseStrList(opts.dns)),
      m_dnsExceptions(parseStrList(opts.dns_exceptions)),
      m_killswitchMode(opts.killswitch_mode),
      m_tunFd(-1),
      m_ifIndex(-1),
      m_netlinkFd(-1),
      m_cancelFd(-1),
      m_up(false),
      m_mtu(0) {}

Tunnel::~Tunnel() {
    stopMonitor();
#if defined(__linux__)
    if (m_tunFd >= 0) {
        ::close(m_tunFd);
    }
#endif
}

int Tunnel::openTun() {
#if defined(__linux__)
    int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, "xtun", IFNAMSIZ - 1);

    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        ::close(fd);
        return -1;
    }

    m_tunFd = fd;
    m_name = ifr.ifr_name;

    // SIOCGIFINDEX is a socket ioctl, not a tun-device one, so it must go
    // through an AF_INET socket rather than the tun fd. The interface is
    // selected by name (ifr_name), not by the socket.
    int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        ::close(fd);
        m_tunFd = -1;
        return -1;
    }

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sock);
        ::close(fd);
        m_tunFd = -1;
        return -1;
    }
    ::close(sock);
    m_ifIndex = ifr.ifr_ifindex;

    m_mtu = mtu();

    startMonitor();
    return 0;
#else
    return -1;
#endif
}

int Tunnel::read(void *buf, size_t len) {
#if defined(__linux__)
    return static_cast<int>(::read(m_tunFd, buf, len));
#else
    (void)buf;
    (void)len;
    return -1;
#endif
}

int Tunnel::write(const void *buf, size_t len) {
#if defined(__linux__)
    return static_cast<int>(::write(m_tunFd, buf, len));
#else
    (void)buf;
    (void)len;
    return -1;
#endif
}

int Tunnel::mtu() const {
#if defined(__linux__)
    int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);

    int result = -1;
    if (::ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
        result = ifr.ifr_mtu;
    }

    ::close(sock);
    return result;
#else
    return -1;
#endif
}

void Tunnel::startMonitor() {
#if defined(__linux__)
    m_netlinkFd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (m_netlinkFd < 0) {
        return;
    }

    struct sockaddr_nl addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    if (::bind(m_netlinkFd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(m_netlinkFd);
        m_netlinkFd = -1;
        return;
    }

    m_cancelFd = ::eventfd(0, EFD_CLOEXEC);
    if (m_cancelFd < 0) {
        ::close(m_netlinkFd);
        m_netlinkFd = -1;
        return;
    }

    m_monitor = std::thread(&Tunnel::monitorLoop, this);
#endif
}

void Tunnel::stopMonitor() {
#if defined(__linux__)
    if (m_monitor.joinable()) {
        uint64_t one = 1;
        (void)::write(m_cancelFd, &one, sizeof(one));
        m_monitor.join();
    }
    if (m_netlinkFd >= 0) {
        ::close(m_netlinkFd);
        m_netlinkFd = -1;
    }
    if (m_cancelFd >= 0) {
        ::close(m_cancelFd);
        m_cancelFd = -1;
    }
#endif
}

void Tunnel::monitorLoop() {
#if defined(__linux__)
    struct pollfd fds[2];
    fds[0].fd = m_netlinkFd;
    fds[0].events = POLLIN;
    fds[1].fd = m_cancelFd;
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
            break;  // cancelled
        }

        if (!(fds[0].revents & POLLIN)) {
            continue;
        }

        int len = static_cast<int>(::recv(m_netlinkFd, buf, sizeof(buf), 0));
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        for (struct nlmsghdr *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type != RTM_NEWLINK) {
                continue;
            }

            struct ifinfomsg *ifi = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nh));
            if (ifi->ifi_index != m_ifIndex) {
                continue;
            }

            bool nowUp = (ifi->ifi_flags & IFF_RUNNING) != 0;
            if (nowUp != m_up.exchange(nowUp) && m_onEvent) {
                m_onEvent(nowUp ? Event::Up : Event::Down);
            }

            int rtaLen = static_cast<int>(IFLA_PAYLOAD(nh));
            for (struct rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, rtaLen);
                 rta = RTA_NEXT(rta, rtaLen)) {
                if (rta->rta_type != IFLA_MTU) {
                    continue;
                }
                int newMtu = *reinterpret_cast<int *>(RTA_DATA(rta));
                if (newMtu != m_mtu.exchange(newMtu) && m_onEvent) {
                    m_onEvent(Event::MtuUpdate);
                }
            }
        }
    }
#endif
}

}

int libxtun_tunnel_new(struct libxtun_tunnel *tun, struct libxtun_tunnel_opts *opts) {
    if (tun == nullptr || opts == nullptr) {
        return -1;
    }

    tun->handle = nullptr;

    if (opts->size < sizeof(*opts)) {
        return -1;
    }

    if (opts->killswitch_mode < LIBXTUN_KILLSWITCH_MODE_DISABLED ||
        opts->killswitch_mode > LIBXTUN_KILLSWITCH_MODE_LAST) {
        return -1;
    }

    auto *obj = new libxtun::Tunnel(*opts);
    if (obj->openTun() != 0) {
        delete obj;
        return -1;
    }

    tun->handle = obj;
    return 0;
}

void libxtun_tunnel_free(struct libxtun_tunnel *tun) {
    if (tun == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Tunnel*>(tun->handle);
    tun->handle = nullptr;
}

