#include "router_macos.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <vector>

namespace {

bool splitCidr(const std::string &cidr, std::string &ip, int &prefix) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        ip = cidr;
        prefix = cidr.find(':') != std::string::npos ? 128 : 32;
    } else {
        ip = cidr.substr(0, slash);
        prefix = std::atoi(cidr.c_str() + slash + 1);
    }
    return !ip.empty();
}

int parseIp(const std::string &ip, int &family, unsigned char out[16]) {
    if (inet_pton(AF_INET, ip.c_str(), out) == 1) {
        family = AF_INET;
        return 4;
    }
    if (inet_pton(AF_INET6, ip.c_str(), out) == 1) {
        family = AF_INET6;
        return 16;
    }
    return -1;
}

// The space a route-message sockaddr occupies: its length rounded up to a 4-byte
// boundary (a zero length still counts as one word), used to walk a dump.
size_t saSize(const struct sockaddr *sa) {
    size_t l = sa->sa_len ? sa->sa_len : sizeof(uint32_t);
    return (l + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
}

// Route-message sockaddrs are packed after the header, each padded to a 4-byte
// boundary. Appends sa (sa_len bytes) at len and advances len past the padding.
void appendSa(char *buf, size_t &len, const void *sa, size_t saLen) {
    std::memcpy(buf + len, sa, saLen);
    len += saLen;
    if (len % sizeof(uint32_t)) {
        len += sizeof(uint32_t) - (len % sizeof(uint32_t));
    }
}

}

namespace libxtun {

int MacosRouter::setMtu(int mtu) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        return -errno;
    }
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;
    int rc = ::ioctl(fd, SIOCSIFMTU, &ifr) < 0 ? -errno : 0;
    ::close(fd);
    return rc;
}

int MacosRouter::setUp() {
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        return -errno;
    }
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        int e = -errno;
        ::close(fd);
        return e;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int rc = ::ioctl(fd, SIOCSIFFLAGS, &ifr) < 0 ? -errno : 0;
    ::close(fd);
    return rc;
}

int MacosRouter::addAddress(const std::string &cidr) {
    std::string ip;
    int prefix;
    if (!splitCidr(cidr, ip, prefix)) {
        return -EINVAL;
    }
    int family;
    unsigned char raw[16];
    if (parseIp(ip, family, raw) < 0) {
        return -EINVAL;
    }

    if (family == AF_INET) {
        int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
            return -errno;
        }
        struct ifaliasreq ifra;
        std::memset(&ifra, 0, sizeof(ifra));
        std::strncpy(ifra.ifra_name, m_ifname.c_str(), IFNAMSIZ - 1);
        auto *addr = reinterpret_cast<struct sockaddr_in *>(&ifra.ifra_addr);
        auto *dst = reinterpret_cast<struct sockaddr_in *>(&ifra.ifra_broadaddr);
        auto *mask = reinterpret_cast<struct sockaddr_in *>(&ifra.ifra_mask);
        addr->sin_family = dst->sin_family = mask->sin_family = AF_INET;
        addr->sin_len = dst->sin_len = mask->sin_len = sizeof(struct sockaddr_in);
        std::memcpy(&addr->sin_addr, raw, 4);
        std::memcpy(&dst->sin_addr, raw, 4);
        std::memset(&mask->sin_addr, 0xff, sizeof(mask->sin_addr));
        int rc = ::ioctl(fd, SIOCAIFADDR, &ifra) < 0 ? -errno : 0;
        ::close(fd);
        return rc;
    }

    int fd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        return -errno;
    }
    struct in6_aliasreq ifra;
    std::memset(&ifra, 0, sizeof(ifra));
    std::strncpy(ifra.ifra_name, m_ifname.c_str(), IFNAMSIZ - 1);
    ifra.ifra_addr.sin6_family = AF_INET6;
    ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
    std::memcpy(&ifra.ifra_addr.sin6_addr, raw, 16);
    ifra.ifra_prefixmask.sin6_family = AF_INET6;
    ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
    std::memset(&ifra.ifra_prefixmask.sin6_addr, 0xff, 16);
    ifra.ifra_lifetime.ia6t_vltime = 0xffffffff;
    ifra.ifra_lifetime.ia6t_pltime = 0xffffffff;
    int rc = ::ioctl(fd, SIOCAIFADDR_IN6, &ifra) < 0 ? -errno : 0;
    ::close(fd);
    return rc;
}

int MacosRouter::rtSend(int family, const unsigned char *dst, int prefix, const void *gw,
                           unsigned gwLen, int flags, unsigned index, bool add) {
    char buf[512];
    std::memset(buf, 0, sizeof(buf));
    auto *rtm = reinterpret_cast<struct rt_msghdr *>(buf);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = add ? RTM_ADD : RTM_DELETE;
    rtm->rtm_index = static_cast<unsigned short>(index);
    rtm->rtm_flags = flags;
    rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    rtm->rtm_seq = m_rtseq++;

    size_t len = sizeof(struct rt_msghdr);

    if (family == AF_INET) {
        struct sockaddr_in sin;
        std::memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_len = sizeof(sin);
        std::memcpy(&sin.sin_addr, dst, 4);
        appendSa(buf, len, &sin, sin.sin_len);
    } else {
        struct sockaddr_in6 sin6;
        std::memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_len = sizeof(sin6);
        std::memcpy(&sin6.sin6_addr, dst, 16);
        appendSa(buf, len, &sin6, sin6.sin6_len);
    }

    appendSa(buf, len, gw, gwLen);

    if (family == AF_INET) {
        struct sockaddr_in mask;
        std::memset(&mask, 0, sizeof(mask));
        mask.sin_family = AF_INET;
        mask.sin_len = sizeof(mask);
        mask.sin_addr.s_addr = prefix == 0 ? 0 : htonl(0xffffffffu << (32 - prefix));
        appendSa(buf, len, &mask, mask.sin_len);
    } else {
        struct sockaddr_in6 mask;
        std::memset(&mask, 0, sizeof(mask));
        mask.sin6_family = AF_INET6;
        mask.sin6_len = sizeof(mask);
        int bytes = prefix / 8;
        std::memset(&mask.sin6_addr, 0xff, bytes);
        if (prefix % 8) {
            mask.sin6_addr.s6_addr[bytes] = static_cast<uint8_t>(0xff << (8 - (prefix % 8)));
        }
        appendSa(buf, len, &mask, mask.sin6_len);
    }

    rtm->rtm_msglen = static_cast<unsigned short>(len);

    int fd = ::socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) {
        return -errno;
    }
    ::shutdown(fd, SHUT_RD);
    ssize_t n = ::write(fd, rtm, len);
    int e = n < 0 ? errno : 0;
    ::close(fd);

    if (n >= 0) {
        return 0;
    }
    if (add && e == EEXIST) {
        return 0;
    }
    if (!add && e == ESRCH) {
        return 0;
    }
    return -e;
}

int MacosRouter::updateRoute(int family, const unsigned char *dst, int prefix, bool add) {
    struct sockaddr_dl sdl;
    std::memset(&sdl, 0, sizeof(sdl));
    sdl.sdl_family = AF_LINK;
    sdl.sdl_index = static_cast<unsigned short>(m_ifindex);
    sdl.sdl_type = IFT_OTHER;
    sdl.sdl_nlen = static_cast<unsigned char>(m_ifname.size());
    sdl.sdl_len = static_cast<unsigned char>(offsetof(struct sockaddr_dl, sdl_data) + sdl.sdl_nlen);
    std::memcpy(sdl.sdl_data, m_ifname.c_str(), sdl.sdl_nlen);
    return rtSend(family, dst, prefix, &sdl, sdl.sdl_len, RTF_STATIC | RTF_UP,
                     static_cast<unsigned>(m_ifindex), add);
}

int MacosRouter::updateScopedRoute(int family, const unsigned char *dst, int prefix,
                                   const unsigned char *gw, unsigned scope, bool add) {
    int flags = RTF_STATIC | RTF_UP | RTF_GATEWAY | RTF_IFSCOPE;
    if (family == AF_INET) {
        struct sockaddr_in sin;
        std::memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_len = sizeof(sin);
        std::memcpy(&sin.sin_addr, gw, 4);
        return rtSend(family, dst, prefix, &sin, sin.sin_len, flags, scope, add);
    }
    struct sockaddr_in6 sin6;
    std::memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_len = sizeof(sin6);
    std::memcpy(&sin6.sin6_addr, gw, 16);
    return rtSend(family, dst, prefix, &sin6, sin6.sin6_len, flags, scope, add);
}

int MacosRouter::updateRouteFor(const std::string &cidr, bool add) {
    std::string ip;
    int prefix;
    if (!splitCidr(cidr, ip, prefix)) {
        return -EINVAL;
    }
    int family;
    unsigned char raw[16];
    if (parseIp(ip, family, raw) < 0) {
        return -EINVAL;
    }
    return updateRoute(family, raw, prefix, add);
}

int MacosRouter::updateFullTunnelRoutes(int family, bool add) {
    unsigned char lo[16];
    unsigned char hi[16];
    std::memset(lo, 0, sizeof(lo));
    std::memset(hi, 0, sizeof(hi));
    hi[0] = 0x80;

    int rc = updateRoute(family, lo, 1, add);
    if (add && rc < 0) {
        return rc;
    }
    rc = updateRoute(family, hi, 1, add);
    if (add && rc < 0) {
        return rc;
    }

    ScopedBypass &sb = family == AF_INET ? m_bypassV4 : m_bypassV6;
    if (add) {
        int idx = 0;
        unsigned char gw[16] = {0};
        if (getGatewayAndIface(family, idx, gw)) {
            rc = updateScopedRoute(family, lo, 1, gw, static_cast<unsigned>(idx), true);
            if (rc < 0) {
                return rc;
            }
            rc = updateScopedRoute(family, hi, 1, gw, static_cast<unsigned>(idx), true);
            if (rc < 0) {
                return rc;
            }
            sb.active = true;
            sb.scope = static_cast<unsigned>(idx);
            std::memcpy(sb.gw, gw, sizeof(sb.gw));
        }
    } else if (sb.active) {
        updateScopedRoute(family, lo, 1, sb.gw, sb.scope, false);
        updateScopedRoute(family, hi, 1, sb.gw, sb.scope, false);
        sb.active = false;
    }
    return 0;
}

int MacosRouter::configureInterface(const std::string &ifname, int ifindex,
                                    const std::vector<std::string> &addresses, int mtu) {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    m_ifname = ifname;
    m_ifindex = ifindex;

    if (mtu > 0) {
        int rc = setMtu(mtu);
        if (rc < 0) {
            return rc;
        }
    }

    int rc = setUp();
    if (rc < 0) {
        return rc;
    }

    for (const auto &addr : addresses) {
        rc = addAddress(addr);
        if (rc < 0) {
            revert();
            return rc;
        }
        m_addresses.push_back(addr);
    }
    return 0;
}

int MacosRouter::setProxyRoutes(const std::vector<std::string> &routes) {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    for (const auto &route : routes) {
        if (route == "0.0.0.0/0") {
            if (!m_fullV4) {
                int rc = updateFullTunnelRoutes(AF_INET, true);
                if (rc < 0) {
                    clearProxyRoutes();
                    return rc;
                }
                m_fullV4 = true;
            }
        } else if (route == "::/0") {
            if (!m_fullV6) {
                int rc = updateFullTunnelRoutes(AF_INET6, true);
                if (rc < 0) {
                    clearProxyRoutes();
                    return rc;
                }
                m_fullV6 = true;
            }
        } else {
            int rc = updateRouteFor(route, true);
            if (rc < 0) {
                clearProxyRoutes();
                return rc;
            }
            m_routes.push_back(route);
        }
    }
    return 0;
}

void MacosRouter::clearProxyRoutes() {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    if (m_fullV4) {
        updateFullTunnelRoutes(AF_INET, false);
        m_fullV4 = false;
    }
    if (m_fullV6) {
        updateFullTunnelRoutes(AF_INET6, false);
        m_fullV6 = false;
    }
    for (const auto &route : m_routes) {
        updateRouteFor(route, false);
    }
    m_routes.clear();
}

void MacosRouter::revert() {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    clearProxyRoutes();
    // The utun and its addresses are destroyed when the tun fd closes.
    m_addresses.clear();
}

bool MacosRouter::getGatewayAndIface(int family, int &ifindex, unsigned char *gw) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, NET_RT_FLAGS, RTF_GATEWAY};
    size_t need = 0;
    if (::sysctl(mib, 6, nullptr, &need, nullptr, 0) < 0 || need == 0) {
        return false;
    }
    std::vector<char> buf(need);
    if (::sysctl(mib, 6, buf.data(), &need, nullptr, 0) < 0) {
        return false;
    }

    char *lim = buf.data() + need;
    for (char *p = buf.data(); p + sizeof(struct rt_msghdr) <= lim;) {
        auto *rtm = reinterpret_cast<struct rt_msghdr *>(p);
        if (rtm->rtm_msglen == 0) {
            break;
        }
        p += rtm->rtm_msglen;

        if ((rtm->rtm_flags & (RTF_GATEWAY | RTF_UP)) != (RTF_GATEWAY | RTF_UP)) {
            continue;
        }
        if (rtm->rtm_flags & RTF_IFSCOPE) {
            continue;
        }
        if (rtm->rtm_index == static_cast<unsigned short>(m_ifindex)) {
            continue;
        }
        if ((rtm->rtm_addrs & (RTA_DST | RTA_GATEWAY)) != (RTA_DST | RTA_GATEWAY)) {
            continue;
        }

        auto *dst = reinterpret_cast<struct sockaddr *>(rtm + 1);
        bool isDefault = dst->sa_len == 0;
        if (!isDefault && dst->sa_family == AF_INET) {
            isDefault = reinterpret_cast<struct sockaddr_in *>(dst)->sin_addr.s_addr == 0;
        }
        if (!isDefault && dst->sa_family == AF_INET6) {
            auto &a = reinterpret_cast<struct sockaddr_in6 *>(dst)->sin6_addr;
            isDefault = true;
            for (int i = 0; i < 16; ++i) {
                if (a.s6_addr[i] != 0) {
                    isDefault = false;
                    break;
                }
            }
        }
        if (!isDefault) {
            continue;
        }

        auto *gwsa = reinterpret_cast<struct sockaddr *>(reinterpret_cast<char *>(dst) + saSize(dst));
        if (family == AF_INET && gwsa->sa_family == AF_INET) {
            std::memcpy(gw, &reinterpret_cast<struct sockaddr_in *>(gwsa)->sin_addr, 4);
            ifindex = rtm->rtm_index;
            return true;
        }
        if (family == AF_INET6 && gwsa->sa_family == AF_INET6) {
            std::memcpy(gw, &reinterpret_cast<struct sockaddr_in6 *>(gwsa)->sin6_addr, 16);
            ifindex = rtm->rtm_index;
            return true;
        }
    }
    return false;
}

uint32_t MacosRouter::bypassToken() {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    int idx = 0;
    unsigned char gw[16] = {0};
    if (!getGatewayAndIface(AF_INET, idx, gw)) {
        return 0;
    }
    return static_cast<uint32_t>(idx);
}

}
