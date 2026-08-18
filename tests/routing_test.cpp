#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "proxy.h"
#include "tunnel.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(__linux__)
#include <fcntl.h>
#include <sched.h>
#elif defined(__APPLE__)
#include <sys/sockio.h>
#endif

namespace {

bool privileged() {
    return ::geteuid() == 0;
}

std::string ifAddr(const std::string &name) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    std::string out;
    if (::ioctl(s, SIOCGIFADDR, &ifr) == 0) {
        char buf[64];
        auto *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
            out = buf;
        }
    }
    ::close(s);
    return out;
}

int ifMtu(const std::string &name) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    int mtu = -1;
    if (::ioctl(s, SIOCGIFMTU, &ifr) == 0) {
        mtu = ifr.ifr_mtu;
    }
    ::close(s);
    return mtu;
}

bool ifUp(const std::string &name) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    bool up = false;
    if (::ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        up = (ifr.ifr_flags & IFF_UP) != 0;
    }
    ::close(s);
    return up;
}

struct FixedRoutesProxy : libxtun::Proxy {
    std::vector<std::string> r;
    const char *name() override { return "fixed"; }
    int start(const libxtun::ProxyIo &) override { return LIBXTUN_OK; }
    void event(libxtun::ProxyEvent) override {}
    void stop() override {}
    std::vector<std::string> routes() override { return r; }
    uint32_t token() const { return m_bypassToken; }
};

libxtun_tunnel_opts routingOpts() {
    libxtun_tunnel_opts opts{};
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
    opts.if_addrs.list = "10.99.0.2/24";
    opts.if_addrs.size = 1;
    opts.mtu = 1400;
    return opts;
}

libxtun_tunnel_opts dualStackOpts() {
    static const char kAddrs[] = "10.99.0.2/24\0fd00::2/64";
    libxtun_tunnel_opts opts{};
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
    opts.if_addrs.list = kAddrs;
    opts.if_addrs.size = 2;
    opts.mtu = 1400;
    return opts;
}

#if defined(__linux__)

bool sh(const std::string &cmd) {
    return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0;
}

// Moves the calling thread into a fresh, empty network namespace and restores
// the original on destruction, so a test can rearrange routing in full
// isolation. Threads spawned while it is active (the tunnel monitor) inherit
// the private namespace.
struct NetnsGuard {
    int fd = -1;
    bool ok = false;

    NetnsGuard() {
        fd = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return;
        }
        if (::unshare(CLONE_NEWNET) != 0) {
            ::close(fd);
            fd = -1;
            return;
        }
        ok = true;
    }

    ~NetnsGuard() {
        if (fd >= 0) {
            ::setns(fd, CLONE_NEWNET);
            ::close(fd);
        }
    }
};

// The interface the kernel would use to reach ip, optionally as if the packet
// carried fwmark (0 = unmarked).
std::string routeGetDev(const std::string &ip, unsigned mark) {
    std::string cmd = "ip route get " + ip;
    if (mark != 0) {
        cmd += " mark " + std::to_string(mark);
    }
    cmd += " 2>/dev/null";
    FILE *f = popen(cmd.c_str(), "r");
    if (f == nullptr) {
        return "";
    }
    char line[512];
    std::string dev;
    if (fgets(line, sizeof(line), f) != nullptr) {
        std::string s(line);
        auto pos = s.find(" dev ");
        if (pos != std::string::npos) {
            pos += 5;
            auto end = s.find(' ', pos);
            dev = s.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        }
    }
    pclose(f);
    return dev;
}

bool routeExists(const std::string &name, const std::string &cidr) {
    std::string cmd = "ip -o route show dev " + name + " table main 2>/dev/null";
    FILE *f = popen(cmd.c_str(), "r");
    if (f == nullptr) {
        return false;
    }
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f) != nullptr) {
        if (std::string(line).find(cidr) != std::string::npos) {
            found = true;
            break;
        }
    }
    pclose(f);
    return found;
}

#elif defined(__APPLE__)

// The interface `route -n get <dst>` resolves to; "default" gives the physical
// uplink. Parses the "interface: <name>" line. A colon in dst selects IPv6.
std::string routeGetIface(const std::string &dst) {
    std::string cmd = "route -n get ";
    if (dst.find(':') != std::string::npos) {
        cmd += "-inet6 ";
    }
    cmd += dst + " 2>/dev/null";
    FILE *f = popen(cmd.c_str(), "r");
    if (f == nullptr) {
        return "";
    }
    char line[512];
    std::string iface;
    while (fgets(line, sizeof(line), f) != nullptr) {
        std::string s(line);
        auto pos = s.find("interface:");
        if (pos != std::string::npos) {
            pos += 10;
            while (pos < s.size() && s[pos] == ' ') {
                ++pos;
            }
            auto end = s.find_first_of(" \n", pos);
            iface = s.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
            break;
        }
    }
    pclose(f);
    return iface;
}

#endif

}  // namespace

#if defined(__linux__)

TEST(Routing, AppliesAddressMtuUpAndRoutes) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring an interface requires root";
    }

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);

    FixedRoutesProxy proxy;
    proxy.r = {"10.88.0.0/24"};
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);

    const std::string name = tunnel.name();
    EXPECT_EQ(ifAddr(name), "10.99.0.2");
    EXPECT_EQ(ifMtu(name), 1400);
    EXPECT_TRUE(ifUp(name));
    EXPECT_TRUE(routeExists(name, "10.88.0.0/24"));
}

TEST(Routing, FullTunnelMarksBypassPhysical) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: network namespaces require root";
    }

    NetnsGuard netns;
    ASSERT_TRUE(netns.ok) << "could not create a private network namespace";

    ASSERT_TRUE(sh("ip link set lo up"));
    ASSERT_TRUE(sh("ip link add dummy0 type dummy")) << "needs the 'dummy' kernel module";
    ASSERT_TRUE(sh("ip addr add 10.10.0.2/24 dev dummy0"));
    ASSERT_TRUE(sh("ip link set dummy0 up"));
    ASSERT_TRUE(sh("ip route add default via 10.10.0.1 dev dummy0"));

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);

    FixedRoutesProxy proxy;
    proxy.r = {"0.0.0.0/0"};
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);

    const std::string name = tunnel.name();
    // Unmarked traffic is captured by the tunnel; the proxy's marked traffic bypasses it.
    EXPECT_EQ(routeGetDev("8.8.8.8", 0), name);
    EXPECT_EQ(routeGetDev("8.8.8.8", 0x7874), "dummy0");
}

TEST(Routing, SwapProxyReplacesRoutes) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring an interface requires root";
    }

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    const std::string name = tunnel.name();

    FixedRoutesProxy a;
    a.r = {"203.0.113.0/24"};
    ASSERT_EQ(tunnel.attachProxy(&a), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);
    EXPECT_TRUE(routeExists(name, "203.0.113.0/24"));

    FixedRoutesProxy b;
    b.r = {"198.51.100.0/24"};
    ASSERT_EQ(tunnel.attachProxy(&b), LIBXTUN_OK);
    EXPECT_FALSE(routeExists(name, "203.0.113.0/24")) << "the old proxy's route survived the swap";
    EXPECT_TRUE(routeExists(name, "198.51.100.0/24"));
}

TEST(Routing, InstallsIPv6Route) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring an interface requires root";
    }

    libxtun_tunnel_opts opts = dualStackOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    const std::string name = tunnel.name();

    FixedRoutesProxy proxy;
    proxy.r = {"2001:db8::/32"};
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);
    EXPECT_EQ(routeGetDev("2001:db8::1", 0), name);
}

#elif defined(__APPLE__)

TEST(Routing, AppliesAddressMtuUpAndSplitRoute) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring a utun requires root";
    }

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);

    FixedRoutesProxy proxy;
    proxy.r = {"203.0.113.0/24"};
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);

    const std::string name = tunnel.name();
    EXPECT_EQ(ifAddr(name), "10.99.0.2");
    EXPECT_EQ(ifMtu(name), 1400);
    EXPECT_TRUE(ifUp(name));
    EXPECT_EQ(routeGetIface("203.0.113.1"), name);
}

TEST(Routing, BypassTokenIsPhysicalDefault) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring a utun requires root";
    }

    const std::string physical = routeGetIface("default");
    if (physical.empty() || physical == "lo0") {
        GTEST_SKIP() << "no physical default route to compare against";
    }

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);

    FixedRoutesProxy proxy;
    proxy.r = {"203.0.113.0/24"};
    // attach (no start) hands the proxy the bypass token: the physical ifindex.
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);

    EXPECT_EQ(proxy.token(), ::if_nametoindex(physical.c_str()));
}

TEST(Routing, FullTunnelCatchAllAndBoundSocketBypass) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring a utun requires root";
    }

    const std::string physical = routeGetIface("default");
    if (physical.empty() || physical == "lo0") {
        GTEST_SKIP() << "no physical uplink to bypass to";
    }
    unsigned physIdx = ::if_nametoindex(physical.c_str());
    const std::string physIp = ifAddr(physical);
    ASSERT_FALSE(physIp.empty());

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    const std::string name = tunnel.name();

    FixedRoutesProxy proxy;
    proxy.r = {"0.0.0.0/0"};
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);

    EXPECT_EQ(routeGetIface("1.1.1.1"), name);

    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(::setsockopt(s, IPPROTO_IP, IP_BOUND_IF, &physIdx, sizeof(physIdx)), 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    ::inet_pton(AF_INET, "1.1.1.1", &dst.sin_addr);
    ASSERT_EQ(::connect(s, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)), 0)
        << "connect failed: " << std::strerror(errno);
    sockaddr_in src{};
    socklen_t slen = sizeof(src);
    ASSERT_EQ(::getsockname(s, reinterpret_cast<sockaddr *>(&src), &slen), 0);
    char buf[64] = {0};
    ::inet_ntop(AF_INET, &src.sin_addr, buf, sizeof(buf));
    ::close(s);

    EXPECT_EQ(std::string(buf), physIp) << "bound socket did not bypass the tunnel";
    EXPECT_NE(std::string(buf), "10.99.0.2");
}

TEST(Routing, SwapProxyReplacesRoutes) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring a utun requires root";
    }

    libxtun_tunnel_opts opts = routingOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    const std::string name = tunnel.name();

    FixedRoutesProxy a;
    a.r = {"203.0.113.0/24"};
    ASSERT_EQ(tunnel.attachProxy(&a), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);
    EXPECT_EQ(routeGetIface("203.0.113.1"), name);

    FixedRoutesProxy b;
    b.r = {"198.51.100.0/24"};
    ASSERT_EQ(tunnel.attachProxy(&b), LIBXTUN_OK);
    EXPECT_NE(routeGetIface("203.0.113.1"), name) << "the old proxy's route survived the swap";
    EXPECT_EQ(routeGetIface("198.51.100.1"), name);
}

TEST(Routing, InstallsIPv6Route) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: configuring a utun requires root";
    }

    libxtun_tunnel_opts opts = dualStackOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    const std::string name = tunnel.name();

    FixedRoutesProxy proxy;
    proxy.r = {"2001:db8::/32"};  // RFC 3849 documentation prefix
    ASSERT_EQ(tunnel.attachProxy(&proxy), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);
    EXPECT_EQ(routeGetIface("2001:db8::1"), name);
}

#endif

#endif  // __linux__ || __APPLE__
