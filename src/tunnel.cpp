#include "tunnel.h"

#include <cstring>

#if defined(__linux__) || defined(__APPLE__)
#include <cerrno>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(__linux__)
#include <cstdint>

#include <poll.h>
#include <sys/eventfd.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#elif defined(__APPLE__)
#include <sys/kern_control.h>
#include <sys/sockio.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_utun.h>
#include <net/route.h>
#include <netinet/in.h>
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

#if defined(_WIN32)

class RunGuard {
  public:
    explicit RunGuard(std::atomic<int> &counter) : m_counter(counter) { m_counter.fetch_add(1); }
    ~RunGuard() { m_counter.fetch_sub(1); }

  private:
    std::atomic<int> &m_counter;
};

#endif

}

namespace libxtun {

Tunnel::Tunnel(const libxtun_tunnel_opts &opts)
    : m_dns(parseStrList(opts.dns)),
      m_dnsExceptions(parseStrList(opts.dns_exceptions)),
      m_killswitchMode(opts.killswitch_mode),
      m_tunFd(-1),
      m_ifIndex(-1),
      m_monitorFd(-1),
      m_cancelFd(-1),
      m_up(false),
      m_mtu(0) {}

Tunnel::~Tunnel() {
    stopMonitor();
#if defined(__linux__) || defined(__APPLE__)
    if (m_tunFd >= 0) {
        ::close(m_tunFd);
    }
#elif defined(_WIN32)
    m_closing.store(true);
    if (m_readWait != nullptr) {
        SetEvent(m_readWait);
    }
    while (m_running.load() != 0) {
        std::this_thread::yield();
    }
    if (m_session != nullptr) {
        m_endSession(m_session);
    }
    if (m_adapter != nullptr) {
        m_closeAdapter(m_adapter);
    }
    if (m_wintun != nullptr) {
        FreeLibrary(m_wintun);
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
#elif defined(__APPLE__)
    int fd = ::socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return -1;
    }

    // Resolve the utun kernel control and connect to it. sc_unit == 0 asks the
    // kernel to assign the next free utun unit (utunN).
    struct ctl_info ctlInfo;
    std::memset(&ctlInfo, 0, sizeof(ctlInfo));
    std::strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name) - 1);
    if (::ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        ::close(fd);
        return -1;
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
        return -1;
    }
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);

    m_tunFd = fd;

    // The kernel picks the name (utunN); read it back off the control socket.
    char ifname[IFNAMSIZ];
    socklen_t ifnameLen = sizeof(ifname);
    if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifnameLen) < 0) {
        ::close(fd);
        m_tunFd = -1;
        return -1;
    }
    m_name = ifname;

    m_ifIndex = static_cast<int>(::if_nametoindex(m_name.c_str()));
    if (m_ifIndex == 0) {
        ::close(fd);
        m_tunFd = -1;
        return -1;
    }

    m_mtu = mtu();

    startMonitor();
    return 0;
#elif defined(_WIN32)
    m_wintun = LoadLibraryExW(L"wintun.dll", nullptr,
                              LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (m_wintun == nullptr) {
        return -1;
    }

    auto *createAdapter = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC *>(
        GetProcAddress(m_wintun, "WintunCreateAdapter"));
    auto *startSession = reinterpret_cast<WINTUN_START_SESSION_FUNC *>(
        GetProcAddress(m_wintun, "WintunStartSession"));
    auto *getReadWaitEvent = reinterpret_cast<WINTUN_GET_READ_WAIT_EVENT_FUNC *>(
        GetProcAddress(m_wintun, "WintunGetReadWaitEvent"));

    m_closeAdapter = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC *>(
        GetProcAddress(m_wintun, "WintunCloseAdapter"));
    m_endSession = reinterpret_cast<WINTUN_END_SESSION_FUNC *>(
        GetProcAddress(m_wintun, "WintunEndSession"));
    m_receivePacket = reinterpret_cast<WINTUN_RECEIVE_PACKET_FUNC *>(
        GetProcAddress(m_wintun, "WintunReceivePacket"));
    m_releaseReceivePacket = reinterpret_cast<WINTUN_RELEASE_RECEIVE_PACKET_FUNC *>(
        GetProcAddress(m_wintun, "WintunReleaseReceivePacket"));
    m_allocateSendPacket = reinterpret_cast<WINTUN_ALLOCATE_SEND_PACKET_FUNC *>(
        GetProcAddress(m_wintun, "WintunAllocateSendPacket"));
    m_sendPacket = reinterpret_cast<WINTUN_SEND_PACKET_FUNC *>(
        GetProcAddress(m_wintun, "WintunSendPacket"));

    if (createAdapter == nullptr || startSession == nullptr ||
        getReadWaitEvent == nullptr || m_closeAdapter == nullptr ||
        m_endSession == nullptr || m_receivePacket == nullptr ||
        m_releaseReceivePacket == nullptr || m_allocateSendPacket == nullptr ||
        m_sendPacket == nullptr) {
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return -1;
    }

    m_adapter = createAdapter(L"xtun", L"WireGuard", nullptr);
    if (m_adapter == nullptr) {
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return -1;
    }

    m_session = startSession(m_adapter, 0x800000);  // 8 MiB ring
    if (m_session == nullptr) {
        m_closeAdapter(m_adapter);
        m_adapter = nullptr;
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return -1;
    }

    m_readWait = getReadWaitEvent(m_session);
    m_name = "xtun";
    m_mtu = m_forcedMtu;
    return 0;
#else
    return -1;
#endif
}

int Tunnel::read(void *buf, size_t len) {
#if defined(__linux__)
    return static_cast<int>(::read(m_tunFd, buf, len));
#elif defined(__APPLE__)
    // utun prepends a 4-byte address-family header; strip it with a scatter
    // read so callers still deal in raw IP packets.
    unsigned char hdr[4];
    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;

    ssize_t n = ::readv(m_tunFd, iov, 2);
    if (n < static_cast<ssize_t>(sizeof(hdr))) {
        return -1;
    }
    return static_cast<int>(n - sizeof(hdr));
#elif defined(_WIN32)
    RunGuard guard(m_running);

    for (;;) {
        if (m_closing.load()) {
            return -1;
        }
        DWORD packetSize = 0;
        BYTE *packet = m_receivePacket(m_session, &packetSize);
        if (packet != nullptr) {
            DWORD n = packetSize < len ? packetSize : static_cast<DWORD>(len);
            std::memcpy(buf, packet, n);
            m_releaseReceivePacket(m_session, packet);
            return static_cast<int>(n);
        }
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
            WaitForSingleObject(m_readWait, INFINITE);
            continue;
        }
        return -1;
    }
#else
    (void)buf;
    (void)len;
    return -1;
#endif
}

int Tunnel::write(const void *buf, size_t len) {
#if defined(__linux__)
    return static_cast<int>(::write(m_tunFd, buf, len));
#elif defined(__APPLE__)
    // utun expects a 4-byte address-family header; prepend it with a scatter
    // write, deriving the family from the IP version nibble.
    if (len == 0) {
        return -1;
    }
    unsigned char version = static_cast<const unsigned char *>(buf)[0] >> 4;
    unsigned char af;
    if (version == 4) {
        af = AF_INET;
    } else if (version == 6) {
        af = AF_INET6;
    } else {
        return -1;
    }

    unsigned char hdr[4] = {0, 0, 0, af};
    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = const_cast<void *>(buf);
    iov[1].iov_len = len;

    ssize_t n = ::writev(m_tunFd, iov, 2);
    if (n < static_cast<ssize_t>(sizeof(hdr))) {
        return -1;
    }
    return static_cast<int>(n - sizeof(hdr));
#elif defined(_WIN32)
    RunGuard guard(m_running);

    if (m_closing.load() || len == 0) {
        return -1;
    }
    BYTE *packet = m_allocateSendPacket(m_session, static_cast<DWORD>(len));
    if (packet == nullptr) {
        return -1;  // ring full => packet dropped
    }
    std::memcpy(packet, buf, len);
    m_sendPacket(m_session, packet);
    return static_cast<int>(len);
#else
    (void)buf;
    (void)len;
    return -1;
#endif
}

int Tunnel::mtu() const {
#if defined(__linux__) || defined(__APPLE__)
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
#elif defined(_WIN32)
    return m_forcedMtu;
#else
    return -1;
#endif
}

void Tunnel::startMonitor() {
#if defined(__linux__)
    m_monitorFd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (m_monitorFd < 0) {
        return;
    }

    struct sockaddr_nl addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    if (::bind(m_monitorFd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(m_monitorFd);
        m_monitorFd = -1;
        return;
    }

    m_cancelFd = ::eventfd(0, EFD_CLOEXEC);
    if (m_cancelFd < 0) {
        ::close(m_monitorFd);
        m_monitorFd = -1;
        return;
    }

    m_monitor = std::thread(&Tunnel::monitorLoop, this);
#elif defined(__APPLE__)
    m_monitorFd = ::socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (m_monitorFd < 0) {
        return;
    }
    ::fcntl(m_monitorFd, F_SETFD, FD_CLOEXEC);

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
    if (m_monitorFd >= 0) {
        ::close(m_monitorFd);
        m_monitorFd = -1;
    }
    if (m_cancelFd >= 0) {
        ::close(m_cancelFd);
        m_cancelFd = -1;
    }
#elif defined(__APPLE__)
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
#endif
}

void Tunnel::monitorLoop() {
#if defined(__linux__)
    struct pollfd fds[2];
    fds[0].fd = m_monitorFd;
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

        int len = static_cast<int>(::recv(m_monitorFd, buf, sizeof(buf), 0));
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
#elif defined(__APPLE__)
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
            break;  // socket shut down => cancelled
        }
        if (n < static_cast<ssize_t>(sizeof(struct if_msghdr))) {
            continue;
        }

        struct if_msghdr *ifm = reinterpret_cast<struct if_msghdr *>(buf);
        if (ifm->ifm_type != RTM_IFINFO || ifm->ifm_index != m_ifIndex) {
            continue;
        }

        bool nowUp = (ifm->ifm_flags & IFF_UP) != 0;
        if (nowUp != m_up.exchange(nowUp) && m_onEvent) {
            m_onEvent(nowUp ? Event::Up : Event::Down);
        }

        int newMtu = static_cast<int>(ifm->ifm_data.ifi_mtu);
        if (newMtu != m_mtu.exchange(newMtu) && m_onEvent) {
            m_onEvent(Event::MtuUpdate);
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
