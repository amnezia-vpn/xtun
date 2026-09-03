#include "router_linux.h"

#include "fwmark.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include <systemd/sd-bus.h>

namespace
{

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

    int LinuxRouter::setMtu(int mtu)
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

    int LinuxRouter::setUp()
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

    int LinuxRouter::updateAddress(const std::string &cidr, bool add)
    {
        std::string ip;
        int prefix;
        if (!splitCidr(cidr, ip, prefix)) {
            return -EINVAL;
        }
        int family;
        unsigned char raw[16];
        int len = parseIp(ip, family, raw);
        if (len < 0) {
            return -EINVAL;
        }

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
        req.ifa.ifa_family = family;
        req.ifa.ifa_prefixlen = static_cast<uint8_t>(prefix);
        req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
        req.ifa.ifa_index = m_ifindex;

        addAttr(&req.nlh, IFA_LOCAL, raw, len);
        addAttr(&req.nlh, IFA_ADDRESS, raw, len);
        return nlSend(&req.nlh);
    }

    int LinuxRouter::updateRouteFor(const std::string &cidr, bool add)
    {
        std::string ip;
        int prefix;
        if (!splitCidr(cidr, ip, prefix)) {
            return -EINVAL;
        }
        int family;
        unsigned char raw[16];
        int len = parseIp(ip, family, raw);
        if (len < 0) {
            return -EINVAL;
        }

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
        req.rtm.rtm_family = family;
        req.rtm.rtm_dst_len = static_cast<uint8_t>(prefix);
        req.rtm.rtm_table = RT_TABLE_MAIN;
        req.rtm.rtm_protocol = RTPROT_BOOT;
        req.rtm.rtm_scope = RT_SCOPE_LINK;
        req.rtm.rtm_type = RTN_UNICAST;

        addAttr(&req.nlh, RTA_DST, raw, len);
        uint32_t oif = static_cast<uint32_t>(m_ifindex);
        addAttr(&req.nlh, RTA_OIF, &oif, sizeof(oif));
        return nlSend(&req.nlh);
    }

    int LinuxRouter::updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                                int suppressPrefixLen, uint32_t priority)
    {
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
        return nlSend(&req.nlh);
    }

    int LinuxRouter::updateFullTunnelRoutes(int family, bool add)
    {
        struct
        {
            struct nlmsghdr nlh;
            struct rtmsg rtm;
            char attr[64];
        } req;
        std::memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtm));
        req.nlh.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        if (add) {
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        }
        req.rtm.rtm_family = family;
        req.rtm.rtm_dst_len = 0;
        req.rtm.rtm_table = RT_TABLE_UNSPEC;
        req.rtm.rtm_protocol = RTPROT_BOOT;
        req.rtm.rtm_scope = RT_SCOPE_LINK;
        req.rtm.rtm_type = RTN_UNICAST;
        uint32_t table = PROXY_TABLE;
        addAttr(&req.nlh, RTA_TABLE, &table, sizeof(table));
        uint32_t oif = static_cast<uint32_t>(m_ifindex);
        addAttr(&req.nlh, RTA_OIF, &oif, sizeof(oif));

        int rc = nlSend(&req.nlh);
        if (add && rc < 0) {
            return rc;
        }

        // Unmarked traffic uses the private table (the tun); the proxy's own marked
        // packets fall through to the main table and reach the physical link.
        rc = updateRule(add, family, true, PROXY_FWMARK, PROXY_TABLE, -1, 32765);
        if (add && rc < 0) {
            return rc;
        }
        // Ignore the main table's default route so more-specific routes (LAN) still win.
        rc = updateRule(add, family, false, 0, RT_TABLE_MAIN, 0, 32764);
        if (add && rc < 0) {
            return rc;
        }
        return 0;
    }

    int LinuxRouter::setDns(const std::vector<std::string> &servers)
    {
        if (servers.empty()) {
            return 0;
        }

        sd_bus *bus = nullptr;
        int r = sd_bus_open_system(&bus);
        if (r < 0) {
            return r;
        }

        sd_bus_message *msg = nullptr;
        sd_bus_error err = SD_BUS_ERROR_NULL;

        r = sd_bus_message_new_method_call(bus, &msg, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                                           "org.freedesktop.resolve1.Manager", "SetLinkDNS");
        if (r >= 0) {
            r = sd_bus_message_append(msg, "i", m_ifindex);
        }
        if (r >= 0) {
            r = sd_bus_message_open_container(msg, 'a', "(iay)");
        }
        for (const auto &s : servers) {
            if (r < 0) {
                break;
            }
            int family;
            unsigned char raw[16];
            int len = parseIp(s, family, raw);
            if (len < 0) {
                continue;
            }
            r = sd_bus_message_open_container(msg, 'r', "iay");
            if (r >= 0) {
                r = sd_bus_message_append(msg, "i", family);
            }
            if (r >= 0) {
                r = sd_bus_message_append_array(msg, 'y', raw, len);
            }
            if (r >= 0) {
                r = sd_bus_message_close_container(msg);
            }
        }
        if (r >= 0) {
            r = sd_bus_message_close_container(msg);
        }
        if (r >= 0) {
            r = sd_bus_call(bus, msg, 0, &err, nullptr);
        }

        if (r >= 0) {
            m_dnsApplied = true;
            sd_bus_error_free(&err);
            err = SD_BUS_ERROR_NULL;
            sd_bus_call_method(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager", "SetLinkDefaultRoute", &err, nullptr, "ib",
                               m_ifindex, 1);
        }

        sd_bus_error_free(&err);
        sd_bus_message_unref(msg);
        sd_bus_unref(bus);
        return r < 0 ? r : 0;
    }

    void LinuxRouter::revertDns()
    {
        if (!m_dnsApplied) {
            return;
        }
        sd_bus *bus = nullptr;
        if (sd_bus_open_system(&bus) < 0) {
            return;
        }
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_call_method(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                           "org.freedesktop.resolve1.Manager", "RevertLink", &err, nullptr, "i", m_ifindex);
        sd_bus_error_free(&err);
        sd_bus_unref(bus);

        m_dnsApplied = false;
    }

    int LinuxRouter::configureInterface(const std::string &ifname, int ifindex,
                                        const std::vector<std::string> &addresses, int mtu)
    {
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
            rc = updateAddress(addr, true);
            if (rc < 0) {
                revert();
                return rc;
            }
            m_addresses.push_back(addr);
        }
        return 0;
    }

    int LinuxRouter::setProxyRoutes(const std::vector<std::string> &routes)
    {
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

    void LinuxRouter::clearProxyRoutes()
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

    void LinuxRouter::revert()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        revertDns();
        clearProxyRoutes();
        for (const auto &addr : m_addresses) {
            updateAddress(addr, false);
        }
        m_addresses.clear();
    }

    int LinuxRouter::bypassSocket(int fd, int family)
    {
        (void)family;
        unsigned mark = PROXY_FWMARK;
        if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
            return -1;
        }
        return 0;
    }

    bool LinuxRouter::bypassChanged()
    {
        return false;
    }

}
