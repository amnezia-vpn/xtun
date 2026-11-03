#include "router_linux.h"

#include "fwmark.h"
#include "xtun.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
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

    template <typename Request>
    bool addAttr(Request &req, int type, const void *data, size_t len)
    {
        if (req.nlh.nlmsg_len > sizeof(req) || len > sizeof(req)) {
            return false;
        }
        const size_t offset = NLMSG_ALIGN(req.nlh.nlmsg_len);
        const size_t attrSize = RTA_SPACE(len);
        if (offset > sizeof(req) || attrSize > sizeof(req) - offset) {
            return false;
        }

        // Use the whole request including its trailing attribute buffer
        auto *rta = reinterpret_cast<struct rtattr *>(reinterpret_cast<char *>(&req) + offset);
        rta->rta_type = type;
        rta->rta_len = static_cast<uint16_t>(RTA_LENGTH(len));
        std::memcpy(RTA_DATA(rta), data, len);
        req.nlh.nlmsg_len = static_cast<uint32_t>(offset + attrSize);
        return true;
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
        // The minimum MTU for IPv6 in Linux is 1280 bytes.
        if (mtu < 1280) {
            const auto isIpv6 = [](const std::string &cidr) {
                const auto prefix = net::IpPrefix::parse(cidr);
                return prefix && prefix->address().family() == AF_INET6;
            };
            if (m_fullV6.route || std::any_of(m_addresses.begin(), m_addresses.end(), isIpv6)
                || std::any_of(m_routes.begin(), m_routes.end(), isIpv6)) {
                return LIBXTUN_ERR_INVALID_ARGS;
            }
        }
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

    libxtun_error LinuxRouter::updateIpAddress(const net::IpPrefix &address, bool add)
    {
        const int family = address.address().family();
        if ((family != AF_INET && family != AF_INET6) || address.bits() > (family == AF_INET ? 32u : 128u)) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        const auto local = address.address().octets();

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
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        }
        req.ifa.ifa_family = family;
        req.ifa.ifa_prefixlen = static_cast<uint8_t>(address.bits());
        req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
        req.ifa.ifa_index = m_ifindex;

        if (!addAttr(req, IFA_LOCAL, local.data(), local.size())
            || !addAttr(req, IFA_ADDRESS, local.data(), local.size())) {
            return LIBXTUN_ERR_SYSTEM;
        }

        const int rc = nlSend(&req.nlh);
        if (rc != 0 && (add || (rc != -EADDRNOTAVAIL && rc != -ENOENT))) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::updateIpRoute(const net::IpPrefix &route, bool add)
    {
        const int family = route.address().family();
        if ((family != AF_INET && family != AF_INET6) || route.bits() > (family == AF_INET ? 32u : 128u)) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        const auto raw = route.address().octets();
        if (route.isDefaultRoute()) {
            if (!std::all_of(raw.begin(), raw.end(), [](std::byte value) { return value == std::byte {}; })) {
                return LIBXTUN_ERR_INVALID_ARGS;
            }
            return updateFullTunnelRoutes(family, add);
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
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        }
        req.rtm.rtm_family = family;
        req.rtm.rtm_dst_len = static_cast<uint8_t>(route.bits());
        req.rtm.rtm_table = RT_TABLE_MAIN;
        req.rtm.rtm_protocol = RTPROT_BOOT;
        req.rtm.rtm_scope = RT_SCOPE_LINK;
        req.rtm.rtm_type = RTN_UNICAST;

        uint32_t oif = static_cast<uint32_t>(m_ifindex);
        if (!addAttr(req, RTA_DST, raw.data(), raw.size()) || !addAttr(req, RTA_OIF, &oif, sizeof(oif))) {
            return LIBXTUN_ERR_SYSTEM;
        }

        const int rc = nlSend(&req.nlh);
        if (rc != 0 && (add || (rc != -ESRCH && rc != -ENOENT))) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
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

        if (!addAttr(req, FRA_PRIORITY, &priority, sizeof(priority))) {
            return LIBXTUN_ERR_SYSTEM;
        }
        if (fwmark != 0 && !addAttr(req, FRA_FWMARK, &fwmark, sizeof(fwmark))) {
            return LIBXTUN_ERR_SYSTEM;
        }
        if (table != 0 && !addAttr(req, FRA_TABLE, &table, sizeof(table))) {
            return LIBXTUN_ERR_SYSTEM;
        }
        if (suppressPrefixLen >= 0) {
            uint32_t spl = static_cast<uint32_t>(suppressPrefixLen);
            if (!addAttr(req, FRA_SUPPRESS_PREFIXLEN, &spl, sizeof(spl))) {
                return LIBXTUN_ERR_SYSTEM;
            }
        }

        const int rc = nlSend(&req.nlh);
        if (rc != 0 && (add || (rc != -ENOENT && rc != -ESRCH))) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::updateFullTunnelRoutes(int family, bool add)
    {
        if (family != AF_INET && family != AF_INET6) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        auto &owned = (family == AF_INET) ? m_fullV4 : m_fullV6;

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
            req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        }
        req.rtm.rtm_family = family;
        req.rtm.rtm_dst_len = 0;
        req.rtm.rtm_table = RT_TABLE_UNSPEC;
        req.rtm.rtm_protocol = RTPROT_BOOT;
        req.rtm.rtm_scope = RT_SCOPE_LINK;
        req.rtm.rtm_type = RTN_UNICAST;
        uint32_t table = PROXY_TABLE;
        uint32_t oif = static_cast<uint32_t>(m_ifindex);
        if (!addAttr(req, RTA_TABLE, &table, sizeof(table)) || !addAttr(req, RTA_OIF, &oif, sizeof(oif))) {
            return LIBXTUN_ERR_SYSTEM;
        }

        if (add) {
            // Set each flag only after its entry has been created successfully.
            if (!owned.route) {
                const int rc = nlSend(&req.nlh);
                if (rc != 0) {
                    return LIBXTUN_ERR_SYSTEM;
                }
                owned.route = true;
            }
            // Traffic with PROXY_FWMARK skips this rule and can use the physical route.
            if (!owned.trafficToTunnelRule) {
                const auto rc =
                        updateRule(true, family, true, PROXY_FWMARK, PROXY_TABLE, -1, RULE_PRIORITY_TUNNEL);
                if (rc != LIBXTUN_OK) {
                    return rc;
                }
                owned.trafficToTunnelRule = true;
            }
            // Specific main-table routes (LAN) still win, but its default route does not.
            if (!owned.mainRoutesWithoutDefaultRule) {
                const auto rc =
                        updateRule(true, family, false, 0, RT_TABLE_MAIN, 0, RULE_PRIORITY_LAN);
                if (rc != LIBXTUN_OK) {
                    return rc;
                }
                owned.mainRoutesWithoutDefaultRule = true;
            }
            return LIBXTUN_OK;
        }

        libxtun_error result = LIBXTUN_OK;
        // Ignore the main table's default route so more-specific routes (LAN) still win.
        if (owned.mainRoutesWithoutDefaultRule) {
            const auto rc =
                    updateRule(false, family, false, 0, RT_TABLE_MAIN, 0, RULE_PRIORITY_LAN);
            if (rc == LIBXTUN_OK) {
                owned.mainRoutesWithoutDefaultRule = false;
            } else {
                result = rc;
            }
        }
        // Unmarked traffic uses the private table (the tun); the proxy's own marked
        // packets fall through to the main table and reach the physical link.
        if (owned.trafficToTunnelRule) {
            const auto rc =
                    updateRule(false, family, true, PROXY_FWMARK, PROXY_TABLE, -1, RULE_PRIORITY_TUNNEL);
            if (rc == LIBXTUN_OK) {
                owned.trafficToTunnelRule = false;
            } else if (result == LIBXTUN_OK) {
                result = rc;
            }
        }
        if (owned.route) {
            const int rc = nlSend(&req.nlh);
            if (rc == 0 || rc == -ESRCH || rc == -ENOENT) {
                owned.route = false;
            } else if (result == LIBXTUN_OK) {
                result = LIBXTUN_ERR_SYSTEM;
            }
        }
        return result;
    }

    libxtun_error LinuxRouter::setDns(const std::vector<std::string> &servers)
    {
        if (servers.empty()) {
            return LIBXTUN_OK;
        }

        sd_bus *bus = nullptr;
        int r = sd_bus_open_system(&bus);
        if (r < 0) {
            return LIBXTUN_ERR_SYSTEM;
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
        return r < 0 ? LIBXTUN_ERR_SYSTEM : LIBXTUN_OK;
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

    libxtun_error LinuxRouter::configureInterface(const std::string &ifname, int ifindex,
                                                  const std::vector<std::string> &addresses, int mtu)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        if (ifname.empty() || ifname.size() >= IFNAMSIZ || ifindex <= 0) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        std::vector<net::IpPrefix> prefixes;
        for (const auto &cidr : addresses) {
            const auto address = net::IpPrefix::parse(cidr);
            if (!address) {
                return LIBXTUN_ERR_INVALID_ARGS;
            }
            prefixes.push_back(*address);
        }
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

        for (const auto &address : prefixes) {
            const auto cidr = address.toString();
            if (std::find(m_addresses.begin(), m_addresses.end(), cidr) != m_addresses.end()) {
                continue;
            }
            if (libxtun_error err = updateIpAddress(address, true); err != LIBXTUN_OK) {
                revert();
                return err;
            }
            m_addresses.push_back(cidr);
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::setProxyRoutes(const std::vector<std::string> &routes)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        for (const auto &cidr : routes) {
            const auto route = net::IpPrefix::parse(cidr);
            if (!route) {
                clearProxyRoutes();
                return LIBXTUN_ERR_INVALID_ARGS;
            }
            const auto normalized = route->toString();
            if (std::find(m_routes.begin(), m_routes.end(), normalized) != m_routes.end()) {
                continue;
            }
            if (libxtun_error err = updateIpRoute(*route, true); err != LIBXTUN_OK) {
                clearProxyRoutes();
                return err;
            }
            // Track every installed route so detach can remove it.
            m_routes.push_back(normalized);
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::clearIpRoutes(int family)
    {
        // A failed full-tunnel setup may have installed only part of its rules/routes.
        if (auto rc = updateFullTunnelRoutes(family, false); rc != LIBXTUN_OK) {
            return rc;
        }
        for (auto it = m_routes.begin(); it != m_routes.end();) {
            const auto route = net::IpPrefix::parse(*it);
            if (!route || route->address().family() != family) {
                ++it;
                continue;
            }
            if (auto rc = updateIpRoute(*route, false); rc != LIBXTUN_OK) {
                return rc;
            }
            it = m_routes.erase(it);
        }
        return LIBXTUN_OK;
    }

    libxtun_error LinuxRouter::clearProxyRoutes()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        libxtun_error result = LIBXTUN_OK;
        for (const int family : { AF_INET, AF_INET6 }) {
            const auto rc = clearIpRoutes(family);
            if (result == LIBXTUN_OK && rc != LIBXTUN_OK) {
                result = rc;
            }
        }
        return result;
    }

    void LinuxRouter::revert()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        revertDns();
        clearProxyRoutes();
        for (auto it = m_addresses.begin(); it != m_addresses.end();) {
            const auto address = net::IpPrefix::parse(*it);
            const auto rc = address ? updateIpAddress(*address, false) : LIBXTUN_ERR_INVALID_ARGS;
            if (rc != LIBXTUN_OK) {
                std::fprintf(stderr, "xtun: failed to remove TUN address %s (%d)\n", it->c_str(), static_cast<int>(rc));
                ++it;
                continue;
            }
            it = m_addresses.erase(it);
        }
    }

    libxtun_error LinuxRouter::protectSocket(int fd)
    {
        unsigned mark = PROXY_FWMARK;
        return ::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0 ? LIBXTUN_OK : LIBXTUN_ERR_SYSTEM;
    }
}
