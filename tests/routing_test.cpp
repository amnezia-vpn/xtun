#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // unshare()/setns() and CLONE_NEWNET
#endif

#include "proxy.h"
#include "tunnel.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#if defined(__linux__)

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

bool privileged() {
    return ::geteuid() == 0;
}

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

struct FixedRoutesProxy : libxtun::Proxy {
    std::vector<std::string> r;
    const char *name() override { return "fixed"; }
    int start(const libxtun::ProxyIo &) override { return LIBXTUN_OK; }
    void event(libxtun::ProxyEvent) override {}
    void stop() override {}
    std::vector<std::string> routes() override { return r; }
};

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

libxtun_tunnel_opts routingOpts() {
    libxtun_tunnel_opts opts{};
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
    opts.if_addrs.list = "10.99.0.2/24";
    opts.if_addrs.size = 1;
    opts.mtu = 1400;
    return opts;
}

}  // namespace

TEST(Routing, AppliesAddressMtuUpAndRoutes) {
    ASSERT_TRUE(privileged()) << "configuring an interface requires root";

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
    ASSERT_TRUE(privileged()) << "network namespaces require root";

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

#endif
