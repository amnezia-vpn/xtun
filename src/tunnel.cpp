#include "tunnel.h"

#include <cstring>

#if defined(__linux__) || defined(__APPLE__)
#include <cerrno>
#include <cstdint>

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(__linux__)
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
      m_ifAddrs(parseStrList(opts.if_addrs)),
      m_confMtu(opts.mtu),
      m_router(Router::create()),
      m_tunFd(-1),
      m_ifIndex(-1),
      m_monitorFd(-1),
      m_cancelFd(-1),
      m_readCancelRd(-1),
      m_readCancelWr(-1),
      m_up(false),
      m_mtu(0) {}

Tunnel::~Tunnel() {
    stopMonitor();
    cancelRead();
    if (m_proxy != nullptr) {
        m_proxy->stop();
        m_proxy->m_tunnel = nullptr;
        m_proxy = nullptr;
    }
    if (m_router != nullptr) {
        m_router->revert();
    }
#if defined(__linux__) || defined(__APPLE__)
    if (m_tunFd >= 0) {
        ::close(m_tunFd);
    }
    if (m_readCancelRd >= 0) {
        ::close(m_readCancelRd);
    }
    if (m_readCancelWr >= 0 && m_readCancelWr != m_readCancelRd) {
        ::close(m_readCancelWr);
    }
#elif defined(_WIN32)
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
#elif defined(__APPLE__)
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
        ::close(fd);
        m_tunFd = -1;
        return LIBXTUN_ERR_SYSTEM;
    }
    m_name = ifname;

    return finishOpen();
#elif defined(_WIN32)
    WINTUN_CREATE_ADAPTER_FUNC *createAdapter;
    WINTUN_OPEN_ADAPTER_FUNC *openAdapter;
    WINTUN_START_SESSION_FUNC *startSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent;
    int rc = loadWintun(createAdapter, openAdapter, startSession, getReadWaitEvent);
    if (rc != LIBXTUN_OK) {
        return rc;
    }
    (void)openAdapter;

    m_adapter = createAdapter(L"xtun", L"WireGuard", nullptr);
    if (m_adapter == nullptr) {
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return LIBXTUN_ERR_DEVICE_CREATE;
    }

    m_name = "xtun";
    return startWintunSession(startSession, getReadWaitEvent);
#else
    return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
#endif
}

int Tunnel::adoptTun(int fd) {
#if defined(__linux__) || defined(__APPLE__)
    fd = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) {
        return errno == EBADF ? LIBXTUN_ERR_INVALID_ARGS : LIBXTUN_ERR_SYSTEM;
    }
#endif
#if defined(__linux__)
    // read()/write() exchange raw IP packets, so the device must have been
    // attached with IFF_TUN | IFF_NO_PI; the flags cannot be changed on an
    // already-attached descriptor.
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    if (::ioctl(fd, TUNGETIFF, &ifr) < 0 ||
        (ifr.ifr_flags & IFF_TUN) == 0 || (ifr.ifr_flags & IFF_NO_PI) == 0) {
        ::close(fd);
        return LIBXTUN_ERR_DEVICE_CREATE;
    }

    m_tunFd = fd;
    m_name = ifr.ifr_name;

    return finishOpen();
#elif defined(__APPLE__)
    char ifname[IFNAMSIZ];
    socklen_t ifnameLen = sizeof(ifname);
    if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifnameLen) < 0) {
        ::close(fd);
        return LIBXTUN_ERR_DEVICE_CREATE;
    }

    m_tunFd = fd;
    m_name = ifname;

    return finishOpen();
#else
    (void)fd;
    return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
#endif
}

int Tunnel::adoptTunByName(const char *name) {
#if defined(__linux__)
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
#elif defined(_WIN32)
    WINTUN_CREATE_ADAPTER_FUNC *createAdapter;
    WINTUN_OPEN_ADAPTER_FUNC *openAdapter;
    WINTUN_START_SESSION_FUNC *startSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent;
    int rc = loadWintun(createAdapter, openAdapter, startSession, getReadWaitEvent);
    if (rc != LIBXTUN_OK) {
        return rc;
    }
    (void)createAdapter;

    WCHAR wname[256];
    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 256) == 0) {
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    m_adapter = openAdapter(wname);
    if (m_adapter == nullptr) {
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return LIBXTUN_ERR_DEVICE_CREATE;
    }

    m_name = name;
    return startWintunSession(startSession, getReadWaitEvent);
#else
    (void)name;
    return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
#endif
}

#if defined(_WIN32)

int Tunnel::loadWintun(WINTUN_CREATE_ADAPTER_FUNC *&createAdapter,
                       WINTUN_OPEN_ADAPTER_FUNC *&openAdapter,
                       WINTUN_START_SESSION_FUNC *&startSession,
                       WINTUN_GET_READ_WAIT_EVENT_FUNC *&getReadWaitEvent) {
    m_wintun = LoadLibraryExW(L"wintun.dll", nullptr,
                              LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (m_wintun == nullptr) {
        return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
    }

    createAdapter = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC *>(
        GetProcAddress(m_wintun, "WintunCreateAdapter"));
    openAdapter = reinterpret_cast<WINTUN_OPEN_ADAPTER_FUNC *>(
        GetProcAddress(m_wintun, "WintunOpenAdapter"));
    startSession = reinterpret_cast<WINTUN_START_SESSION_FUNC *>(
        GetProcAddress(m_wintun, "WintunStartSession"));
    getReadWaitEvent = reinterpret_cast<WINTUN_GET_READ_WAIT_EVENT_FUNC *>(
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

    if (createAdapter == nullptr || openAdapter == nullptr ||
        startSession == nullptr || getReadWaitEvent == nullptr ||
        m_closeAdapter == nullptr || m_endSession == nullptr ||
        m_receivePacket == nullptr || m_releaseReceivePacket == nullptr ||
        m_allocateSendPacket == nullptr || m_sendPacket == nullptr) {
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
    }

    return LIBXTUN_OK;
}

int Tunnel::startWintunSession(WINTUN_START_SESSION_FUNC *startSession,
                               WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent) {
    m_session = startSession(m_adapter, 0x800000);  // 8 MiB ring
    if (m_session == nullptr) {
        m_closeAdapter(m_adapter);
        m_adapter = nullptr;
        FreeLibrary(m_wintun);
        m_wintun = nullptr;
        return LIBXTUN_ERR_DEVICE_CREATE;
    }

    m_readWait = getReadWaitEvent(m_session);
    m_mtu = m_forcedMtu;
    return LIBXTUN_OK;
}

#endif

#if defined(__linux__) || defined(__APPLE__)

int Tunnel::finishOpen() {
#if defined(__linux__)
    // SIOCGIFINDEX is a socket ioctl, not a tun-device one, so it must go
    // through an AF_INET socket rather than the tun fd. The interface is
    // selected by name (ifr_name), not by the socket.
    int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        ::close(m_tunFd);
        m_tunFd = -1;
        return LIBXTUN_ERR_SYSTEM;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sock);
        ::close(m_tunFd);
        m_tunFd = -1;
        return LIBXTUN_ERR_SYSTEM;
    }
    ::close(sock);
    m_ifIndex = ifr.ifr_ifindex;
#elif defined(__APPLE__)
    m_ifIndex = static_cast<int>(::if_nametoindex(m_name.c_str()));
    if (m_ifIndex == 0) {
        ::close(m_tunFd);
        m_tunFd = -1;
        return LIBXTUN_ERR_SYSTEM;
    }
#endif

#if defined(__linux__)
    m_readCancelRd = m_readCancelWr = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (m_readCancelRd < 0) {
        ::close(m_tunFd);
        m_tunFd = -1;
        return LIBXTUN_ERR_SYSTEM;
    }
#elif defined(__APPLE__)
    int cancelPipe[2];
    if (::pipe(cancelPipe) < 0) {
        ::close(m_tunFd);
        m_tunFd = -1;
        return LIBXTUN_ERR_SYSTEM;
    }
    ::fcntl(cancelPipe[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(cancelPipe[1], F_SETFD, FD_CLOEXEC);
    ::fcntl(cancelPipe[0], F_SETFL, O_NONBLOCK);
    m_readCancelRd = cancelPipe[0];
    m_readCancelWr = cancelPipe[1];
#endif

    m_mtu = mtu();

    startMonitor();
    return LIBXTUN_OK;
}

#endif

int Tunnel::read(void *buf, size_t len) {
#if defined(__linux__) || defined(__APPLE__)
    if (m_tunFd < 0) {
        return -1;
    }

    struct pollfd fds[2];
    fds[0].fd = m_tunFd;
    fds[0].events = POLLIN;
    fds[1].fd = m_readCancelRd;
    fds[1].events = POLLIN;

    for (;;) {
        if (::poll(fds, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (fds[1].revents & POLLIN) {
            return -1;
        }
        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            break;
        }
    }
#endif
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

int Tunnel::attachProxy(Proxy *proxy) {
    if (proxy == nullptr || proxy->m_tunnel != nullptr || m_proxy != nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    ProxyIo io;
    io.read = [this](void *buf, int len) { return this->read(buf, static_cast<size_t>(len)); };
    io.write = [this](const void *buf, int len) { return this->write(buf, static_cast<size_t>(len)); };
    io.mtu = [this]() { return this->currentMtu(); };

#if defined(__linux__) || defined(__APPLE__)
    if (m_readCancelRd >= 0) {
        uint64_t drained;
        while (::read(m_readCancelRd, &drained, sizeof(drained)) > 0) {
        }
    }
#elif defined(_WIN32)
    m_closing.store(false);
#endif

    m_proxy = proxy;
    proxy->m_tunnel = this;

    int rc = proxy->start(io);
    if (rc != LIBXTUN_OK) {
        proxy->m_tunnel = nullptr;
        m_proxy = nullptr;
        return rc;
    }

    if (m_router != nullptr) {
        NetworkConfig cfg;
        cfg.addresses = m_ifAddrs;
        cfg.dns = m_dns;
        cfg.mtu = m_confMtu;
        cfg.routes = proxy->routes();
        cfg.bypass = proxy->endpoints();

        if (!cfg.addresses.empty() || !cfg.routes.empty() || !cfg.bypass.empty() ||
            !cfg.dns.empty() || cfg.mtu > 0) {
            if (m_router->apply(m_name, m_ifIndex, cfg) != 0) {
                m_router->revert();
                proxy->stop();
                proxy->m_tunnel = nullptr;
                m_proxy = nullptr;
                return LIBXTUN_ERR_SYSTEM;
            }
        }
    }
    return LIBXTUN_OK;
}

void Tunnel::detachProxy(Proxy *proxy) {
    if (m_proxy == proxy) {
        m_proxy = nullptr;
    }
}

void Tunnel::cancelRead() {
#if defined(__linux__) || defined(__APPLE__)
    if (m_readCancelWr >= 0) {
        uint64_t one = 1;
        (void)::write(m_readCancelWr, &one, sizeof(one));
    }
#elif defined(_WIN32)
    m_closing.store(true);
    if (m_readWait != nullptr) {
        SetEvent(m_readWait);
    }
#endif
}

void Tunnel::emit(Event ev) {
    if (m_onEvent) {
        m_onEvent(ev);
    }
    if (m_proxy == nullptr) {
        return;
    }

    switch (ev) {
        case Event::Up:
            m_proxy->event(ProxyEvent::Up);
            break;
        case Event::Down:
            m_proxy->event(ProxyEvent::Down);
            break;
        case Event::MtuUpdate:
            m_proxy->event(ProxyEvent::MtuUpdate);
            break;
    }
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
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
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
            if (nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
                // Only the physical default route matters here; our own /1 and
                // bypass writes carry a non-zero dst_len and are ignored.
                struct rtmsg *rtm = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nh));
                if (rtm->rtm_dst_len == 0 && rtm->rtm_table == RT_TABLE_MAIN &&
                    m_router != nullptr) {
                    m_router->refresh();
                }
                continue;
            }
            if (nh->nlmsg_type != RTM_NEWLINK) {
                continue;
            }

            struct ifinfomsg *ifi = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nh));
            if (ifi->ifi_index != m_ifIndex) {
                continue;
            }

            bool nowUp = (ifi->ifi_flags & IFF_RUNNING) != 0;
            if (nowUp != m_up.exchange(nowUp)) {
                emit(nowUp ? Event::Up : Event::Down);
            }

            int rtaLen = static_cast<int>(IFLA_PAYLOAD(nh));
            for (struct rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, rtaLen);
                 rta = RTA_NEXT(rta, rtaLen)) {
                if (rta->rta_type != IFLA_MTU) {
                    continue;
                }
                int newMtu = *reinterpret_cast<int *>(RTA_DATA(rta));
                if (newMtu != m_mtu.exchange(newMtu)) {
                    emit(Event::MtuUpdate);
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
        if (nowUp != m_up.exchange(nowUp)) {
            emit(nowUp ? Event::Up : Event::Down);
        }

        int newMtu = static_cast<int>(ifm->ifm_data.ifi_mtu);
        if (newMtu != m_mtu.exchange(newMtu)) {
            emit(Event::MtuUpdate);
        }
    }
#endif
}

}

int libxtun_tunnel_new(struct libxtun_tunnel *tun, struct libxtun_tunnel_opts *opts) {
    if (tun == nullptr || opts == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    if (opts->size < sizeof(*opts)) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    if (opts->killswitch_mode < LIBXTUN_KILLSWITCH_MODE_DISABLED ||
        opts->killswitch_mode > LIBXTUN_KILLSWITCH_MODE_LAST) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *obj = new libxtun::Tunnel(*opts);

    int rc = obj->openTun();
    if (rc != LIBXTUN_OK) {
        delete obj;
        return rc;
    }

    tun->handle = obj;
    return LIBXTUN_OK;
}

int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, int fd) {
    if (tun == nullptr || fd < 0) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    // The device was created and configured elsewhere, so no tunnel options
    // accompany it: empty DNS lists, killswitch disabled.
    struct libxtun_tunnel_opts opts;
    std::memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;

    auto *obj = new libxtun::Tunnel(opts);

    int rc = obj->adoptTun(fd);
    if (rc != LIBXTUN_OK) {
        delete obj;
        return rc;
    }

    tun->handle = obj;
    return LIBXTUN_OK;
}

int libxtun_tunnel_new_from_name(struct libxtun_tunnel *tun, const char *name) {
    if (tun == nullptr || name == nullptr || name[0] == '\0') {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    struct libxtun_tunnel_opts opts;
    std::memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;

    auto *obj = new libxtun::Tunnel(opts);

    int rc = obj->adoptTunByName(name);
    if (rc != LIBXTUN_OK) {
        delete obj;
        return rc;
    }

    tun->handle = obj;
    return LIBXTUN_OK;
}

void libxtun_tunnel_free(struct libxtun_tunnel *tun) {
    if (tun == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Tunnel*>(tun->handle);
    tun->handle = nullptr;
}

int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy) {
    if (tun == nullptr || tun->handle == nullptr || proxy == nullptr || proxy->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel*>(tun->handle);
    return obj->attachProxy(reinterpret_cast<libxtun::Proxy*>(proxy->handle));
}
