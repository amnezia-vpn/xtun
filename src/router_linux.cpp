#include "router_linux.h"

#include "fwmark.h"
#include "xtun.h"

#include <cerrno>
#include <cstdint>
#include <cstring>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

namespace
{
    void addAttr(struct nlmsghdr *nlh, int type, const void *data, int len)
    {
        struct rtattr *rta =
                reinterpret_cast<struct rtattr *>(reinterpret_cast<char *>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
        rta->rta_type = type;
        rta->rta_len = RTA_LENGTH(len);
        std::memcpy(RTA_DATA(rta), data, len);
        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }

    // Opens a NETLINK_ROUTE socket and sends nlh, returning the fd (the caller
    // closes it) so it can read the reply however it needs, or -errno on failure.
    int nlConnect(struct nlmsghdr *nlh)
    {
        int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) {
            return -errno;
        }

        struct sockaddr_nl sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;

        struct iovec iov = { nlh, nlh->nlmsg_len };
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(sa);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (::sendmsg(fd, &msg, 0) < 0) {
            int e = -errno;
            ::close(fd);
            return e;
        }
        return fd;
    }

    int nlSend(struct nlmsghdr *nlh)
    {
        int fd = nlConnect(nlh);
        if (fd < 0) {
            return fd;
        }

        char buf[8192];
        struct iovec riov = { buf, sizeof(buf) };
        struct msghdr rmsg;
        std::memset(&rmsg, 0, sizeof(rmsg));
        rmsg.msg_iov = &riov;
        rmsg.msg_iovlen = 1;

        ssize_t n = ::recvmsg(fd, &rmsg, 0);
        ::close(fd);
        if (n < 0) {
            return -errno;
        }

        for (struct nlmsghdr *rh = reinterpret_cast<struct nlmsghdr *>(buf); NLMSG_OK(rh, n); rh = NLMSG_NEXT(rh, n)) {
            if (rh->nlmsg_type == NLMSG_ERROR) {
                return reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(rh))->error;
            }
        }
        return 0;
    }
}

namespace libxtun
{
    libxtun_error LinuxRouter::setMtu(int mtu)
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

    libxtun_error LinuxRouter::setUp()
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

    libxtun_error LinuxRouter::updateAddress(const net::IpPrefix &prefix, bool add)
    {
        const auto octets = prefix.address().octets();

        struct
        {
            struct nlmsghdr nlh;
            struct ifaddrmsg ifa;
            char attr[64];
        } req;
        std::memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifa));
        req.nlh.nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        if (add) {
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        }
        req.ifa.ifa_family = static_cast<uint8_t>(prefix.address().family());
        req.ifa.ifa_prefixlen = static_cast<uint8_t>(prefix.bits());
        req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
        req.ifa.ifa_index = m_ifindex;

        addAttr(&req.nlh, IFA_LOCAL, octets.data(), static_cast<int>(octets.size()));
        addAttr(&req.nlh, IFA_ADDRESS, octets.data(), static_cast<int>(octets.size()));
        
        if (int rc = nlSend(&req.nlh); rc != 0) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::updateRouteFor(const net::IpPrefix &prefix, bool add)
    {
        const auto octets = prefix.address().octets();

        struct
        {
            struct nlmsghdr nlh;
            struct rtmsg rtm;
            char attr[128];
        } req;
        std::memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtm));
        req.nlh.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        if (add) {
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        }
        req.rtm.rtm_family = static_cast<uint8_t>(prefix.address().family());
        req.rtm.rtm_dst_len = static_cast<uint8_t>(prefix.bits());
        req.rtm.rtm_table = RT_TABLE_UNSPEC;
        req.rtm.rtm_protocol = RTPROT_BOOT;
        req.rtm.rtm_scope = RT_SCOPE_LINK;
        req.rtm.rtm_type = RTN_UNICAST;

        uint32_t table = PROXY_TABLE;
        addAttr(&req.nlh, RTA_TABLE, &table, sizeof(table));
        if (prefix.bits() > 0) {
            addAttr(&req.nlh, RTA_DST, octets.data(), static_cast<int>(octets.size()));
        }
        uint32_t oif = static_cast<uint32_t>(m_ifindex);
        addAttr(&req.nlh, RTA_OIF, &oif, sizeof(oif));

        if (int rc = nlSend(&req.nlh); rc != 0) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                                          int suppressPrefixLen, uint32_t priority, const net::IpPrefix *dst)
    {
        if (add) {
            updateRule(false, family, invert, fwmark, table, suppressPrefixLen, priority, dst);
        }

        struct
        {
            struct nlmsghdr nlh;
            struct fib_rule_hdr frh;
            char attr[64];
        } req;
        std::memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.frh));
        req.nlh.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        if (add) {
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        }
        req.frh.family = static_cast<uint8_t>(family);
        req.frh.action = FR_ACT_TO_TBL;
        req.frh.table = RT_TABLE_UNSPEC;
        if (invert) {
            req.frh.flags |= FIB_RULE_INVERT;
        }

        addAttr(&req.nlh, FRA_PRIORITY, &priority, sizeof(priority));
        if (fwmark != 0) {
            addAttr(&req.nlh, FRA_FWMARK, &fwmark, sizeof(fwmark));
        }
        if (table != 0) {
            addAttr(&req.nlh, FRA_TABLE, &table, sizeof(table));
        }
        if (suppressPrefixLen >= 0) {
            uint32_t spl = static_cast<uint32_t>(suppressPrefixLen);
            addAttr(&req.nlh, FRA_SUPPRESS_PREFIXLEN, &spl, sizeof(spl));
        }
        if (dst != nullptr) {
            const auto octets = dst->address().octets();
            addAttr(&req.nlh, FRA_DST, octets.data(), static_cast<int>(octets.size()));
            req.frh.dst_len = static_cast<uint8_t>(dst->bits());
        }

        if (int rc = nlSend(&req.nlh); rc != 0) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::updateExcludeRule(const net::IpPrefix &prefix, bool add)
    {
        return updateRule(add, prefix.address().family(), false, 0, RT_TABLE_MAIN, -1, RULE_PRIORITY_EXCLUDE, &prefix);
    }

    libxtun_error LinuxRouter::updateTunnelRules(int family, bool add)
    {
        // Unmarked traffic uses the private table (the tun); the proxy's own marked
        // packets fall through to the main table and reach the physical link.
        if (auto err = updateRule(add, family, true, PROXY_FWMARK, PROXY_TABLE, -1, RULE_PRIORITY_TUNNEL); add && err != LIBXTUN_OK) {
            return err;
        }

        // Ignore the main table's default route so more-specific routes (LAN) still win.
        if (auto err = updateRule(add, family, false, 0, RT_TABLE_MAIN, 0, RULE_PRIORITY_LAN); add && err != LIBXTUN_OK) {
            return err;
        }

        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::configureInterface(const std::string &ifname, int ifindex,
                                                  const std::vector<net::IpPrefix> &addresses, int mtu)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        m_ifname = ifname;
        m_ifindex = ifindex;

        if (mtu > 0) {
            if (libxtun_error err = setMtu(mtu); err != LIBXTUN_OK) {
                return err;
            }
        }

        if (libxtun_error err = setUp(); err != LIBXTUN_OK) {
            return err;
        }

        for (const auto &addr : addresses) {
            if (libxtun_error err = updateAddress(addr, true); err != LIBXTUN_OK) {
                revert();
                return err;
            }
            m_addresses.push_back(addr);
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::addProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                              const std::vector<net::IpPrefix> &excludes)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        for (const auto &route : routes) {
            if (libxtun_error err = updateRouteFor(route, true); err != LIBXTUN_OK) {
                clearProxyRoutes();
                return err;
            }
            m_routes.push_back(route);

            const int family = route.address().family();
            if (bool &rules = family == AF_INET ? m_rulesV4 : m_rulesV6; !rules) {
                if (libxtun_error err = updateTunnelRules(family, true); err != LIBXTUN_OK) {
                    clearProxyRoutes();
                    return err;
                }
                rules = true;
            }
        }
        for (const auto &exclude : excludes) {
            if (libxtun_error err = updateExcludeRule(exclude, true); err != LIBXTUN_OK) {
                clearProxyRoutes();
                return err;
            }
            m_excludes.push_back(exclude);
        }
        return LIBXTUN_OK;
    }

    void LinuxRouter::removeProxyRoutes()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        for (const auto &exclude : m_excludes) {
            updateExcludeRule(exclude, false);
        }
        m_excludes.clear();
        if (m_rulesV4) {
            updateTunnelRules(AF_INET, false);
            m_rulesV4 = false;
        }
        if (m_rulesV6) {
            updateTunnelRules(AF_INET6, false);
            m_rulesV6 = false;
        }
        for (const auto &route : m_routes) {
            updateRouteFor(route, false);
        }
        m_routes.clear();
    }

    void LinuxRouter::revert()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        clearProxyRoutes();
        for (const auto &addr : m_addresses) {
            updateAddress(addr, false);
        }
        m_addresses.clear();
    }

    void LinuxRouter::protectSocket(int fd)
    {
        unsigned mark = PROXY_FWMARK;
        ::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    }
}
