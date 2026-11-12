#include "router_macos.h"
#include "xtun.h"

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

namespace
{

    const unsigned char DEFAULT_LOWER_HALF[16] = { 0x00 };
    const unsigned char DEFAULT_UPPER_HALF[16] = { 0x80 };

    bool splitCidr(const std::string &cidr, std::string &ip, int &prefix)
    {
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

    int parseIp(const std::string &ip, int &family, unsigned char out[16])
    {
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
    size_t saSize(const struct sockaddr *sa)
    {
        size_t l = sa->sa_len ? sa->sa_len : sizeof(uint32_t);
        return (l + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
    }

    // Route-message sockaddrs are packed after the header, each padded to a 4-byte
    // boundary. Appends sa (sa_len bytes) at len and advances len past the padding.
    void appendSa(char *buf, size_t &len, const void *sa, size_t saLen)
    {
        std::memcpy(buf + len, sa, saLen);
        len += saLen;
        if (len % sizeof(uint32_t)) {
            len += sizeof(uint32_t) - (len % sizeof(uint32_t));
        }
    }

}

namespace libxtun
{

    libxtun_error MacosRouter::setMtu(int mtu)
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
            return LIBXTUN_ERR_SYSTEM;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);
        ifr.ifr_mtu = mtu;
        int rc = ::ioctl(fd, SIOCSIFMTU, &ifr);
        ::close(fd);
        return rc < 0 ? LIBXTUN_ERR_SYSTEM : LIBXTUN_OK;
    }

    libxtun_error MacosRouter::setUp()
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
            return LIBXTUN_ERR_SYSTEM;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, m_ifname.c_str(), IFNAMSIZ - 1);
        if (::ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
            ::close(fd);
            return LIBXTUN_ERR_SYSTEM;
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        int rc = ::ioctl(fd, SIOCSIFFLAGS, &ifr);
        ::close(fd);
        return rc < 0 ? LIBXTUN_ERR_SYSTEM : LIBXTUN_OK;
    }

    libxtun_error MacosRouter::addAddress(const std::string &cidr)
    {
        std::string ip;
        int prefix;
        if (!splitCidr(cidr, ip, prefix)) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        int family;
        unsigned char raw[16];
        if (parseIp(ip, family, raw) < 0) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        if (family == AF_INET) {
            int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if (fd < 0) {
                return LIBXTUN_ERR_SYSTEM;
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
            int rc = ::ioctl(fd, SIOCAIFADDR, &ifra);
            ::close(fd);
            return rc < 0 ? LIBXTUN_ERR_SYSTEM : LIBXTUN_OK;
        }

        int fd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
            return LIBXTUN_ERR_SYSTEM;
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
        int rc = ::ioctl(fd, SIOCAIFADDR_IN6, &ifra);
        ::close(fd);
        return rc < 0 ? LIBXTUN_ERR_SYSTEM : LIBXTUN_OK;
    }

    libxtun_error MacosRouter::rtSend(int family, const unsigned char *dst, int prefix, const void *gw, unsigned gwLen,
                                      int flags, unsigned index, bool add)
    {
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
            return LIBXTUN_ERR_SYSTEM;
        }
        ::shutdown(fd, SHUT_RD);
        ssize_t n = ::write(fd, rtm, len);
        int e = n < 0 ? errno : 0;
        ::close(fd);

        if (n >= 0) {
            return LIBXTUN_OK;
        }
        if (add && e == EEXIST) {
            return LIBXTUN_OK;
        }
        if (!add && e == ESRCH) {
            return LIBXTUN_OK;
        }
        return LIBXTUN_ERR_SYSTEM;
    }

    libxtun_error MacosRouter::updateRoute(int family, const unsigned char *dst, int prefix, bool add)
    {
        struct sockaddr_dl sdl;
        std::memset(&sdl, 0, sizeof(sdl));
        sdl.sdl_family = AF_LINK;
        sdl.sdl_index = static_cast<unsigned short>(m_ifindex);
        sdl.sdl_type = IFT_OTHER;
        sdl.sdl_nlen = static_cast<unsigned char>(m_ifname.size());
        sdl.sdl_len = static_cast<unsigned char>(offsetof(struct sockaddr_dl, sdl_data) + sdl.sdl_nlen);
        std::memcpy(sdl.sdl_data, m_ifname.c_str(), sdl.sdl_nlen);
        return rtSend(family, dst, prefix, &sdl, sdl.sdl_len, RTF_STATIC | RTF_UP, static_cast<unsigned>(m_ifindex), add);
    }

    libxtun_error MacosRouter::updateScopedRoute(int family, const unsigned char *dst, int prefix,
                                                 const unsigned char *gw, unsigned scope, bool add)
    {
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

    libxtun_error MacosRouter::updateRouteFor(const net::IpPrefix &prefix, bool add)
    {
        const auto octets = prefix.address().octets();
        return updateRoute(prefix.address().family(), reinterpret_cast<const unsigned char *>(octets.data()),
                           static_cast<int>(prefix.bits()), add);
    }

    libxtun_error MacosRouter::updateFullTunnelRoutes(int family, bool add)
    {
        if (libxtun_error err = updateRoute(family, DEFAULT_LOWER_HALF, 1, add); add && err != LIBXTUN_OK) {
            return err;
        }
        if (libxtun_error err = updateRoute(family, DEFAULT_UPPER_HALF, 1, add); add && err != LIBXTUN_OK) {
            return err;
        }

        return updateUplinkRoutes(family, family == AF_INET ? m_uplinkV4 : m_uplinkV6, add);
    }

    libxtun_error MacosRouter::updateUplinkRoutes(int family, const Uplink &uplink, bool add)
    {
        if (uplink.ifindex == 0) {
            return LIBXTUN_OK;
        }
        if (libxtun_error err = updateScopedRoute(family, DEFAULT_LOWER_HALF, 1, uplink.gw, uplink.ifindex, add);
            add && err != LIBXTUN_OK) {
            return err;
        }
        if (libxtun_error err = updateScopedRoute(family, DEFAULT_UPPER_HALF, 1, uplink.gw, uplink.ifindex, add);
            add && err != LIBXTUN_OK) {
            updateScopedRoute(family, DEFAULT_LOWER_HALF, 1, uplink.gw, uplink.ifindex, false);
            return err;
        }
        return LIBXTUN_OK;
    }

    libxtun_error MacosRouter::configureInterface(const std::string &ifname, int ifindex,
                                                  const std::vector<std::string> &addresses, int mtu)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        m_ifname = ifname;
        m_ifindex = ifindex;
        m_uplinkV4 = getGatewayAndIface(AF_INET);
        m_uplinkV6 = getGatewayAndIface(AF_INET6);

        if (mtu > 0) {
            if (libxtun_error err = setMtu(mtu); err != LIBXTUN_OK) {
                return err;
            }
        }

        if (libxtun_error err = setUp(); err != LIBXTUN_OK) {
            return err;
        }

        for (const auto &addr : addresses) {
            if (libxtun_error err = addAddress(addr); err != LIBXTUN_OK) {
                revert();
                return err;
            }
            m_addresses.push_back(addr);
        }
        return LIBXTUN_OK;
    }

    libxtun_error MacosRouter::setProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                              const std::vector<net::IpPrefix> &excludes)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        for (const auto &route : routes) {
            const int family = route.address().family();
            if (route.isDefaultRoute()) {
                if (bool &full = family == AF_INET ? m_fullV4 : m_fullV6; !full) {
                    if (libxtun_error err = updateFullTunnelRoutes(family, true); err != LIBXTUN_OK) {
                        clearProxyRoutes();
                        return err;
                    }
                    full = true;
                }
            } else {
                if (libxtun_error err = updateRouteFor(route, true); err != LIBXTUN_OK) {
                    clearProxyRoutes();
                    return err;
                }
                m_routes.push_back(route);
            }
        }
        return LIBXTUN_OK;
    }

    void MacosRouter::clearProxyRoutes()
    {
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

    void MacosRouter::revert()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        clearProxyRoutes();
        // The utun and its addresses are destroyed when the tun fd closes.
        m_addresses.clear();
    }

    MacosRouter::Uplink MacosRouter::getGatewayAndIface(int family)
    {
        int mib[6] = { CTL_NET, PF_ROUTE, 0, family, NET_RT_FLAGS, RTF_GATEWAY };
        size_t need = 0;
        if (::sysctl(mib, 6, nullptr, &need, nullptr, 0) < 0 || need == 0) {
            return {};
        }
        std::vector<char> buf(need);
        if (::sysctl(mib, 6, buf.data(), &need, nullptr, 0) < 0) {
            return {};
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
            Uplink uplink;
            uplink.ifindex = rtm->rtm_index;
            if (family == AF_INET && gwsa->sa_family == AF_INET) {
                std::memcpy(uplink.gw, &reinterpret_cast<struct sockaddr_in *>(gwsa)->sin_addr, 4);
                return uplink;
            }
            if (family == AF_INET6 && gwsa->sa_family == AF_INET6) {
                std::memcpy(uplink.gw, &reinterpret_cast<struct sockaddr_in6 *>(gwsa)->sin6_addr, 16);
                return uplink;
            }
        }
        return {};
    }

    void MacosRouter::onRouteChanged()
    {
        bool uplinkChanged = false;
        {
            std::lock_guard<std::recursive_mutex> lock(m_mtx);
            for (const int family : { AF_INET, AF_INET6 }) {
                Uplink &previous = family == AF_INET ? m_uplinkV4 : m_uplinkV6;
                const Uplink current = getGatewayAndIface(family);
                if (current == previous) {
                    continue;
                }
                const bool full = family == AF_INET ? m_fullV4 : m_fullV6;
                if (full) {
                    updateUplinkRoutes(family, previous, false);
                    updateUplinkRoutes(family, current, true);
                }
                previous = current;
                uplinkChanged = true;
            }
        }
        if (uplinkChanged) {
            m_onUplinkChanged();
        }
    }

    void MacosRouter::protectSocket(int fd)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        const unsigned idx = m_uplinkV4.ifindex;
        if (idx == 0) {
            return;
        }

        ::setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
        ::setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
    }
}
