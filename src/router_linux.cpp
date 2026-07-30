#include "router_linux.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#ifdef XTUN_HAVE_SYSTEMD
#include <systemd/sd-bus.h>
#endif

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

void addAttr(struct nlmsghdr *nlh, int type, const void *data, int len) {
    struct rtattr *rta = reinterpret_cast<struct rtattr *>(
        reinterpret_cast<char *>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    std::memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

int nlSend(struct nlmsghdr *nlh) {
    int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -errno;
    }

    struct sockaddr_nl sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    struct iovec iov = {nlh, nlh->nlmsg_len};
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

    char buf[8192];
    struct iovec riov = {buf, sizeof(buf)};
    struct msghdr rmsg;
    std::memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;

    ssize_t n = ::recvmsg(fd, &rmsg, 0);
    ::close(fd);
    if (n < 0) {
        return -errno;
    }

    for (struct nlmsghdr *rh = reinterpret_cast<struct nlmsghdr *>(buf);
         NLMSG_OK(rh, n); rh = NLMSG_NEXT(rh, n)) {
        if (rh->nlmsg_type == NLMSG_ERROR) {
            return reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(rh))->error;
        }
    }
    return 0;
}

}

namespace libxtun {

int LinuxRouter::setMtu(int mtu) {
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

int LinuxRouter::setUp() {
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

int LinuxRouter::changeAddress(const std::string &cidr, bool add) {
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

    struct {
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

int LinuxRouter::changeRoute(const std::string &cidr, bool add) {
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

    struct {
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

int LinuxRouter::setDns(const std::vector<std::string> &servers) {
    if (servers.empty()) {
        return 0;
    }

#ifndef XTUN_HAVE_SYSTEMD
    (void)servers;
    return 0;
#else
    sd_bus *bus = nullptr;
    int r = sd_bus_open_system(&bus);
    if (r < 0) {
        return r;
    }

    sd_bus_message *msg = nullptr;
    sd_bus_error err = SD_BUS_ERROR_NULL;

    r = sd_bus_message_new_method_call(bus, &msg, "org.freedesktop.resolve1",
                                       "/org/freedesktop/resolve1",
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
                           "org.freedesktop.resolve1.Manager", "SetLinkDefaultRoute", &err,
                           nullptr, "ib", m_ifindex, 1);
    }

    sd_bus_error_free(&err);
    sd_bus_message_unref(msg);
    sd_bus_unref(bus);
    return r < 0 ? r : 0;
#endif
}

void LinuxRouter::revertDns() {
    if (!m_dnsApplied) {
        return;
    }
#ifdef XTUN_HAVE_SYSTEMD
    sd_bus *bus = nullptr;
    if (sd_bus_open_system(&bus) < 0) {
        return;
    }
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_call_method(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                       "org.freedesktop.resolve1.Manager", "RevertLink", &err, nullptr, "i",
                       m_ifindex);
    sd_bus_error_free(&err);
    sd_bus_unref(bus);
#endif
    m_dnsApplied = false;
}

int LinuxRouter::apply(const std::string &ifname, int ifindex, const NetworkConfig &cfg) {
    m_ifname = ifname;
    m_ifindex = ifindex;

    if (cfg.mtu > 0) {
        int rc = setMtu(cfg.mtu);
        if (rc < 0) {
            return rc;
        }
    }

    int rc = setUp();
    if (rc < 0) {
        return rc;
    }

    for (const auto &addr : cfg.addresses) {
        rc = changeAddress(addr, true);
        if (rc < 0) {
            revert();
            return rc;
        }
        m_addresses.push_back(addr);
    }

    for (const auto &route : cfg.routes) {
        rc = changeRoute(route, true);
        if (rc < 0) {
            revert();
            return rc;
        }
        m_routes.push_back(route);
    }

    rc = setDns(cfg.dns);
    if (rc < 0) {
        revert();
        return rc;
    }

    return 0;
}

void LinuxRouter::revert() {
    revertDns();
    for (const auto &route : m_routes) {
        changeRoute(route, false);
    }
    m_routes.clear();
    for (const auto &addr : m_addresses) {
        changeAddress(addr, false);
    }
    m_addresses.clear();
}

}
