#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include "memtun.h"
#include "proto/awg.h"
#include "proxy.h"
#include "tunnel.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/wait.h>
    #include <unistd.h>

    #include <cstring>
#endif

#if defined(__linux__)
    #include "util/spawn.h"

    #include <sched.h>

    #include <linux/if_ether.h>
    #include <linux/if_packet.h>

    #include <cstdlib>
#elif defined(__APPLE__)
    #include "util/spawn.h"

    #include <net/bpf.h>
    #include <net/route.h>
    #include <sys/ioctl.h>
    #include <sys/sysctl.h>

    #include <cerrno>
#elif defined(_WIN32)
    #include <iphlpapi.h>
    #include <windows.h>
    #include <winsock2.h>
    #include <wintun.h>
    #include <ws2tcpip.h>
#endif

#if defined(__linux__)
extern char **environ;
#endif

namespace
{
    libxtun_tunnel_opts realtunOpts()
    {
        static const char *ifAddrs[] = { "10.9.9.1/24", nullptr };
        libxtun_tunnel_opts opts {};
        opts.size = sizeof(opts);
        opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        opts.if_addrs = ifAddrs;
        opts.mtu = 1420;
        return opts;
    }

#if defined(__linux__)

    bool iproute(const std::vector<std::string> &args)
    {
        for (const char *path : { "/usr/sbin/ip", "/sbin/ip" }) {
            if (::access(path, X_OK) == 0) {
                return static_cast<bool>(libxtun::spawn::run(path, args, {}));
            }
        }
        return false;
    }

    constexpr const char *NETNS_MARKER = "XTUN_NETNS_CHILD";

    bool insidePrivateNetns()
    {
        return ::getenv(NETNS_MARKER) != nullptr;
    }

    // unshare(CLONE_NEWNET) moves only the calling thread, and goxtun's Go runtime
    // already holds threads elsewhere: the namespace has to be entered before exec.
    int runTestInPrivateNetns()
    {
        const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
        if (info == nullptr) {
            return -1;
        }

        std::string exe = "/proc/self/exe";
        std::string filter = std::string("--gtest_filter=") + info->test_suite_name() + "." + info->name();
        std::vector<char *> argv { exe.data(), filter.data(), nullptr };

        // execve only reads the environment strings, so the inherited ones are
        // pointed at rather than copied.
        std::string marker = std::string(NETNS_MARKER) + "=1";
        std::vector<char *> envp;
        for (char **e = ::environ; *e != nullptr; ++e) {
            envp.push_back(*e);
        }
        envp.push_back(marker.data());
        envp.push_back(nullptr);

        const pid_t pid = ::fork();
        if (pid < 0) {
            return -1;
        }
        if (pid == 0) {
            if (::unshare(CLONE_NEWNET) == 0) {
                ::execve(exe.c_str(), argv.data(), envp.data());
            }
            ::_exit(127);
        }

        int status = 0;
        if (::waitpid(pid, &status, 0) < 0) {
            return -1;
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

#endif // defined(__linux__)

    constexpr const char *PRIV_KEY_A = "YHJIKcg6kMlHqmHvpdetXH9300wKO4NxqX1L+v9h20A=";
    constexpr const char *PUB_KEY_A = "dpY/lgMy5OZPe6EVFl25AYL8hCsNEPxzO2uZZdzLnlo=";
    constexpr const char *PRIV_KEY_B = "CPbRqDXAuXNShMCXDVQ6d7mKeVAk2isLmqSNOnVWGWs=";
    constexpr const char *PUB_KEY_B = "sB1wCAUCSBg8mrN8n4mPMAs4Z2C9QUCu3i6Emfb9omo=";

    constexpr int PORT_A = 56911;
    constexpr int PORT_B = 56912;

    constexpr const char *AWG_PARAMS = "Jc = 2\n"
                                       "Jmin = 8\n"
                                       "Jmax = 16\n"
                                       "S1 = 4\n"
                                       "S2 = 6\n"
                                       "H1 = 1234567891\n"
                                       "H2 = 1234567892\n"
                                       "H3 = 1234567893\n"
                                       "H4 = 1234567894\n";

    libxtun::proto::awg::Config confA(const std::string &allowed = "0.0.0.0/0", const std::string &host = "127.0.0.1")
    {
        const std::string str = std::string("[Interface]\n") + "PrivateKey = " + PRIV_KEY_A + "\n"
                + "ListenPort = " + std::to_string(PORT_A) + "\n" + AWG_PARAMS
                + "\n"
                  "[Peer]\n"
                + "PublicKey = " + PUB_KEY_B + "\n" + "Endpoint = " + host + ":" + std::to_string(PORT_B)
                + "\n"
                  "AllowedIPs = "
                + allowed
                + "\n"
                  "PersistentKeepalive = 5\n";
        return libxtun::proto::awg::Config::fromConf(str).value();
    }

    libxtun::proto::awg::Config confB(const std::string &host = "127.0.0.1")
    {
        const std::string str = std::string("[Interface]\n") + "PrivateKey = " + PRIV_KEY_B + "\n"
                + "ListenPort = " + std::to_string(PORT_B) + "\n" + AWG_PARAMS
                + "\n"
                  "[Peer]\n"
                + "PublicKey = " + PUB_KEY_A + "\n" + "Endpoint = " + host + ":" + std::to_string(PORT_A)
                + "\n"
                  "AllowedIPs = 10.9.9.1/32\n";
        return libxtun::proto::awg::Config::fromConf(str).value();
    }

    libxtun::proto::awg::Config confRemote()
    {
        const std::string str = std::string("[Interface]\n") + "PrivateKey = " + PRIV_KEY_A + "\n"
                + "ListenPort = " + std::to_string(PORT_A)
                + "\n"
                  "Jc = 2\n"
                  "Jmin = 8\n"
                  "Jmax = 16\n"
                  "S1 = 4\n"
                  "S2 = 6\n"
                  "H1 = 1234567891\n"
                  "H2 = 1234567892\n"
                  "H3 = 1234567893\n"
                  "H4 = 1234567894\n"
                  "\n"
                  "[Peer]\n"
                + "PublicKey = " + PUB_KEY_B
                + "\n"
                  "Endpoint = 203.0.113.2:51820\n"
                  "AllowedIPs = 0.0.0.0/0\n"
                  "PersistentKeepalive = 5\n";
        return libxtun::proto::awg::Config::fromConf(str).value();
    }

    bool contains(const std::vector<unsigned char> &hay, const std::string &needle)
    {
        return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
    }

    class SpyProxy : public libxtun::Proxy
    {
    public:
        const char *name() override
        {
            return "spy";
        }
        int start(libxtun::TunnelIo &) override
        {
            return LIBXTUN_OK;
        }
        void event(libxtun::ProxyEvent) override
        {
        }
        void stop() override
        {
        }
        libxtun::ProxyProfile profile() const override
        {
            return {};
        }

        void registerBypass(int fd, int family)
        {
            registerBypassSocket(fd, family);
        }
    };

#if defined(__linux__)

    int openCaptureAll()
    {
        int cap = ::socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
        if (cap < 0) {
            return -1;
        }
        int fl = ::fcntl(cap, F_GETFL, 0);
        ::fcntl(cap, F_SETFL, fl | O_NONBLOCK);
        return cap;
    }

    // Drain every buffered frame, noting whether the app destination and/or the
    // proxy's endpoint were seen crossing the tunnel interface (dst IP at offset 16
    // of the IPv4 header, which is where an AF_PACKET SOCK_DGRAM read begins).
    void drainTunnel(int cap, unsigned tunidx, const unsigned char app[4], const unsigned char proxy[4], bool &sawApp,
                     bool &sawProxy)
    {
        unsigned char pkt[2048];
        struct sockaddr_ll sll;
        for (;;) {
            socklen_t len = sizeof(sll);
            ssize_t n = ::recvfrom(cap, pkt, sizeof(pkt), 0, reinterpret_cast<sockaddr *>(&sll), &len);
            if (n < 0) {
                return;
            }
            if (n < 20 || (pkt[0] >> 4) != 4 || static_cast<unsigned>(sll.sll_ifindex) != tunidx) {
                continue;
            }
            if (std::memcmp(pkt + 16, app, 4) == 0) {
                sawApp = true;
            }
            if (std::memcmp(pkt + 16, proxy, 4) == 0) {
                sawProxy = true;
            }
        }
    }

#elif defined(__APPLE__)

    // True if the host has a usable default route. A UDP connect only resolves a
    // route and picks a source; nothing is sent.
    bool hasDefaultRoute()
    {
        int s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            return false;
        }
        sockaddr_in d {};
        d.sin_family = AF_INET;
        d.sin_port = htons(53);
        ::inet_pton(AF_INET, "1.1.1.1", &d.sin_addr);
        bool ok = ::connect(s, reinterpret_cast<sockaddr *>(&d), sizeof(d)) == 0;
        ::close(s);
        return ok;
    }

    libxtun::proto::awg::Config confSplit()
    {
        const std::string str = "[Interface]\n"
                                "PrivateKey = YHJIKcg6kMlHqmHvpdetXH9300wKO4NxqX1L+v9h20A=\n"
                                "ListenPort = 56911\n"
                                "Jc = 2\nJmin = 8\nJmax = 16\nS1 = 4\nS2 = 6\n"
                                "H1 = 1234567891\nH2 = 1234567892\nH3 = 1234567893\nH4 = 1234567894\n"
                                "\n"
                                "[Peer]\n"
                                "PublicKey = sB1wCAUCSBg8mrN8n4mPMAs4Z2C9QUCu3i6Emfb9omo=\n"
                                "Endpoint = 203.0.113.2:51820\n"
                                "AllowedIPs = 203.0.113.0/24\n"
                                "PersistentKeepalive = 5\n";
        return libxtun::proto::awg::Config::fromConf(str).value();
    }

    // Opens a BPF device tapping ifname in immediate, non-blocking mode; returns the
    // kernel's required read buffer length in blen.
    int openBpf(const std::string &ifname, size_t &blen)
    {
        int fd = -1;
        for (int i = 0; i < 64; ++i) {
            std::string dev = "/dev/bpf" + std::to_string(i);
            fd = ::open(dev.c_str(), O_RDWR | O_CLOEXEC);
            if (fd >= 0) {
                break;
            }
            if (errno == ENOENT) {
                return -1;
            }
        }
        if (fd < 0) {
            return -1;
        }

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
        unsigned yes = 1;
        unsigned len = 0;
        if (::ioctl(fd, BIOCSETIF, &ifr) < 0 || ::ioctl(fd, BIOCIMMEDIATE, &yes) < 0 || ::ioctl(fd, BIOCGBLEN, &len) < 0
            || len == 0) {
            ::close(fd);
            return -1;
        }
        blen = len;
        int fl = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        return fd;
    }

    void drainBpf(int fd, size_t blen, const unsigned char app[4], const unsigned char proxy[4], bool &sawApp,
                  bool &sawProxy)
    {
        std::vector<char> buf(blen);
        for (;;) {
            ssize_t n = ::read(fd, buf.data(), blen);
            if (n <= 0) {
                return;
            }
            char *p = buf.data();
            char *lim = buf.data() + n;
            while (p + sizeof(struct bpf_hdr) <= lim) {
                auto *bh = reinterpret_cast<struct bpf_hdr *>(p);
                unsigned char *frame = reinterpret_cast<unsigned char *>(p) + bh->bh_hdrlen;
                unsigned c = bh->bh_caplen;
                const unsigned char *ip = nullptr;
                if (c >= 20 && (frame[0] >> 4) == 4) {
                    ip = frame;
                } else if (c >= 24 && (frame[4] >> 4) == 4) {
                    ip = frame + 4;
                }
                if (ip != nullptr) {
                    if (std::memcmp(ip + 16, app, 4) == 0) {
                        sawApp = true;
                    }
                    if (std::memcmp(ip + 16, proxy, 4) == 0) {
                        sawProxy = true;
                    }
                }
                unsigned step = BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
                if (step == 0) {
                    break;
                }
                p += step;
            }
        }
    }

    bool ifconfig(const std::vector<std::string> &args)
    {
        return static_cast<bool>(libxtun::spawn::run("/sbin/ifconfig", args, {}));
    }

    bool route(const std::vector<std::string> &args)
    {
        return static_cast<bool>(libxtun::spawn::run("/sbin/route", args, {}));
    }

    std::string shOut(const std::string &cmd)
    {
        std::string out;
        FILE *f = ::popen(cmd.c_str(), "r");
        if (f == nullptr) {
            return out;
        }
        char b[256];
        size_t n;
        while ((n = ::fread(b, 1, sizeof(b), f)) > 0) {
            out.append(b, n);
        }
        ::pclose(f);
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) {
            out.pop_back();
        }
        return out;
    }

    int macDefaultIfindex()
    {
        int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY };
        size_t need = 0;
        if (::sysctl(mib, 6, nullptr, &need, nullptr, 0) < 0 || need == 0) {
            return 0;
        }
        std::vector<char> buf(need);
        if (::sysctl(mib, 6, buf.data(), &need, nullptr, 0) < 0) {
            return 0;
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
            if ((rtm->rtm_addrs & (RTA_DST | RTA_GATEWAY)) != (RTA_DST | RTA_GATEWAY)) {
                continue;
            }
            auto *dst = reinterpret_cast<struct sockaddr *>(rtm + 1);
            bool isDefault = dst->sa_len == 0
                    || (dst->sa_family == AF_INET && reinterpret_cast<struct sockaddr_in *>(dst)->sin_addr.s_addr == 0);
            if (isDefault) {
                return rtm->rtm_index;
            }
        }
        return 0;
    }

    unsigned boundIfindex(int fd)
    {
        unsigned idx = 0;
        socklen_t len = sizeof(idx);
        if (::getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, &len) != 0) {
            return 0;
        }
        return idx;
    }

    unsigned waitForBinding(int fd, unsigned want, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        unsigned seen = boundIfindex(fd);
        while (seen != want && std::chrono::steady_clock::now() < deadline) {
            ::usleep(50 * 1000);
            seen = boundIfindex(fd);
        }
        return seen;
    }

    struct RoamSim
    {
        std::string feth;
        std::string origGw;
        bool changed = false;

        bool setup()
        {
            feth = shOut("ifconfig feth create");
            if (feth.empty()) {
                return false;
            }
            if (!ifconfig({ feth, "inet", "10.77.0.1/24", "up" })) {
                return false;
            }
            origGw = shOut("route -n get default 2>/dev/null | awk '/gateway:/{print $2}'");
            if (origGw.empty()) {
                return false;
            }
            if (!route({ "-n", "change", "default", "10.77.0.254" })) {
                return false;
            }
            changed = true;
            return true;
        }

        ~RoamSim()
        {
            if (changed && !origGw.empty()) {
                route({ "-n", "change", "default", origGw });
            }
            if (!feth.empty()) {
                ifconfig({ feth, "destroy" });
            }
        }
    };

#endif

} // namespace

#if defined(__linux__)

TEST(AwgRealTun, FullTunnelDeliversThroughKernelTun)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: real kernel tun + netns require root";
    }

    if (!insidePrivateNetns()) {
        ASSERT_EQ(runTestInPrivateNetns(), 0)
                << "the test failed in its private network namespace; see the child output above";
        return;
    }
    ASSERT_TRUE(iproute({ "link", "set", "lo", "up" })) << "loopback is needed for the AWG handshake";

    // Peer B: a second AWG instance behind an in-memory tun.
    MemTun tunB;
    libxtun::proto::Awg b(confB());
    b.setInterface("xtunrtb");
    ASSERT_EQ(b.start(tunB), LIBXTUN_OK);

    // Side A: a real kernel tun carrying a real AWG proxy, full-tunnel routed.
    libxtun_tunnel_opts opts = realtunOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);

    libxtun::proto::Awg a(confA());
    ASSERT_EQ(tunnel.attachProxy(&a), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);

    a.event(libxtun::ProxyEvent::Up);
    b.event(libxtun::ProxyEvent::Up);

    // A datagram from A's tun address toward B's tunnel IP: the kernel routes it
    // into the real tun, A encrypts and sends it to B, B decrypts it into memtun.
    int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(s, 0);

    sockaddr_in src {};
    src.sin_family = AF_INET;
    ::inet_pton(AF_INET, "10.9.9.1", &src.sin_addr);
    ASSERT_EQ(::bind(s, reinterpret_cast<sockaddr *>(&src), sizeof(src)), 0);

    sockaddr_in dst {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    ::inet_pton(AF_INET, "10.9.9.2", &dst.sin_addr);

    const std::string payload = "xtun-realtun-ping";
    std::vector<unsigned char> got;
    bool delivered = false;

    // Long enough for one handshake retransmit: an initiation that reaches a peer
    // which is not running yet is dropped, and RekeyTimeout is 5s.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!delivered && std::chrono::steady_clock::now() < deadline) {
        ::sendto(s, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
        if (tunB.awaitDelivery(got, std::chrono::milliseconds(250)) && contains(got, payload)) {
            delivered = true;
        }
    }

    ::close(s);
    tunB.cancel();
    b.stop();

    ASSERT_TRUE(delivered) << "packet did not traverse the real tun to peer B";
}

TEST(AwgRealTun, MarkedHandshakeBypassesTunnel)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: real kernel tun + netns require root";
    }

    if (!insidePrivateNetns()) {
        ASSERT_EQ(runTestInPrivateNetns(), 0)
                << "the test failed in its private network namespace; see the child output above";
        return;
    }

    ASSERT_TRUE(iproute({ "link", "set", "lo", "up" }));
    ASSERT_TRUE(iproute({ "link", "add", "phys0", "type", "dummy" })) << "needs the 'dummy' module";
    ASSERT_TRUE(iproute({ "addr", "add", "10.0.0.1/24", "dev", "phys0" }));
    ASSERT_TRUE(iproute({ "link", "set", "phys0", "up" }));
    ASSERT_TRUE(iproute({ "route", "add", "default", "via", "10.0.0.254", "dev", "phys0" }));
    ASSERT_TRUE(iproute({ "neigh", "add", "10.0.0.254", "lladdr", "02:00:00:00:00:99", "dev", "phys0" }));

    int cap = openCaptureAll();
    ASSERT_GE(cap, 0);
    unsigned char proxyDst[4];
    unsigned char appDst[4];
    ::inet_pton(AF_INET, "203.0.113.2", proxyDst);
    ::inet_pton(AF_INET, "10.9.9.2", appDst);

    libxtun_tunnel_opts opts = realtunOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    unsigned tunidx = ::if_nametoindex(tunnel.name().c_str());

    libxtun::proto::Awg a(confRemote());
    ASSERT_EQ(tunnel.attachProxy(&a), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);
    a.event(libxtun::ProxyEvent::Up);

    int inj = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(inj, 0);
    sockaddr_in src {};
    src.sin_family = AF_INET;
    ::inet_pton(AF_INET, "10.9.9.1", &src.sin_addr);
    ::bind(inj, reinterpret_cast<sockaddr *>(&src), sizeof(src));
    sockaddr_in dst {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    ::inet_pton(AF_INET, "10.9.9.2", &dst.sin_addr);

    // Drain for a fixed window so the handshake (sent on Up) has time to be routed
    // and, if the mark ever failed, to surface on the tun before we assert.
    bool sawApp = false;
    bool sawProxy = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < deadline) {
        const char poke = 0;
        ::sendto(inj, &poke, sizeof(poke), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
        drainTunnel(cap, tunidx, appDst, proxyDst, sawApp, sawProxy);
        ::usleep(50 * 1000);
    }

    ::close(inj);
    ::close(cap);

    EXPECT_TRUE(sawApp) << "sanity check failed: ordinary traffic never crossed the tun";
    ASSERT_FALSE(sawProxy) << "the proxy's own handshake was pulled into the tunnel - the fwmark bypass failed";
}

#elif defined(__APPLE__)

TEST(AwgRealTun, MarkedHandshakeBypassesTunnel)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: real utun + BPF require root";
    }
    if (!hasDefaultRoute()) {
        GTEST_SKIP() << "no physical uplink for the handshake to bypass to";
    }

    unsigned char proxyDst[4];
    unsigned char appDst[4];
    ::inet_pton(AF_INET, "203.0.113.2", proxyDst);
    ::inet_pton(AF_INET, "203.0.113.5", appDst);

    libxtun_tunnel_opts opts = realtunOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    const std::string name = tunnel.name();

    size_t blen = 0;
    int cap = openBpf(name, blen);
    ASSERT_GE(cap, 0) << "could not open a BPF device on the utun";

    libxtun::proto::Awg a(confSplit());
    ASSERT_EQ(tunnel.attachProxy(&a), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);
    a.event(libxtun::ProxyEvent::Up);

    int inj = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(inj, 0);
    sockaddr_in src {};
    src.sin_family = AF_INET;
    ::inet_pton(AF_INET, "10.9.9.1", &src.sin_addr);
    ::bind(inj, reinterpret_cast<sockaddr *>(&src), sizeof(src));
    sockaddr_in dst {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    ::inet_pton(AF_INET, "203.0.113.5", &dst.sin_addr);

    // Poke the tun so the proxy has something to send and initiates a handshake.
    bool sawApp = false;
    bool sawProxy = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < deadline) {
        const char poke = 0;
        ::sendto(inj, &poke, sizeof(poke), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
        drainBpf(cap, blen, appDst, proxyDst, sawApp, sawProxy);
        ::usleep(50 * 1000);
    }

    ::close(inj);
    ::close(cap);

    EXPECT_TRUE(sawApp) << "sanity check failed: ordinary traffic never crossed the utun";
    ASSERT_FALSE(sawProxy) << "the proxy's own handshake was pulled into the tunnel - the fwmark bypass failed";
}

TEST(AwgRealTun, RoamRemarkFollowsDefaultRouteChange)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: feth + default route changes require root";
    }
    if (macDefaultIfindex() == 0) {
        GTEST_SKIP() << "no physical default route to roam away from";
    }

    SpyProxy spy;

    libxtun_tunnel_opts opts = realtunOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    ASSERT_EQ(tunnel.attachProxy(&spy), LIBXTUN_OK);

    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sock, 0);
    ::fcntl(sock, F_SETFD, FD_CLOEXEC);
    spy.registerBypass(sock, AF_INET);

    int before = macDefaultIfindex();
    ASSERT_EQ(boundIfindex(sock), static_cast<unsigned>(before))
            << "registering the socket did not bind it to the current uplink";

    RoamSim roam;
    if (!roam.setup()) {
        ::close(sock);
        GTEST_SKIP() << "could not create feth + point the default route at it on this host";
    }

    unsigned fethIdx = ::if_nametoindex(roam.feth.c_str());
    ASSERT_NE(fethIdx, 0u);

    unsigned seen = waitForBinding(sock, fethIdx, std::chrono::seconds(3));
    int after = macDefaultIfindex();
    ::close(sock);

    if (static_cast<unsigned>(after) != fethIdx) {
        GTEST_SKIP() << "the feth default did not take (winner=" << after
                     << "); cannot exercise the roam trigger on this host";
    }
    EXPECT_NE(before, static_cast<int>(fethIdx));
    EXPECT_EQ(seen, fethIdx) << "the default route moved to feth but the registered socket was not rebound";
}

#elif defined(_WIN32)

namespace
{

    constexpr bool VERBOSE = false;

    void logA(const char *str, void *)
    {
        if (VERBOSE) {
            std::fprintf(stderr, "[A] %s\n", str);
        }
    }

    void logB(const char *str, void *)
    {
        if (VERBOSE) {
            std::fprintf(stderr, "[B] %s\n", str);
        }
    }

    unsigned boundIfindex(SOCKET s)
    {
        DWORD scope = 0;
        int len = sizeof(scope);
        if (::getsockopt(s, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<char *>(&scope), &len) != 0) {
            return 0;
        }
        return static_cast<unsigned>(scope);
    }

    unsigned waitForBinding(SOCKET s, unsigned want, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        unsigned seen = boundIfindex(s);
        while (seen != want && std::chrono::steady_clock::now() < deadline) {
            ::Sleep(50);
            seen = boundIfindex(s);
        }
        return seen;
    }

    std::string localPhysicalIp()
    {
        PMIB_IPFORWARD_TABLE2 routes = nullptr;
        if (::GetIpForwardTable2(AF_INET, &routes) != NO_ERROR || routes == nullptr) {
            return "";
        }
        NET_IFINDEX ifidx = 0;
        ULONG best = ~0UL;
        for (ULONG i = 0; i < routes->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2 &r = routes->Table[i];
            if (r.DestinationPrefix.PrefixLength == 0 && r.Metric < best) {
                best = r.Metric;
                ifidx = r.InterfaceIndex;
            }
        }
        ::FreeMibTable(routes);
        if (ifidx == 0) {
            return "";
        }

        PMIB_UNICASTIPADDRESS_TABLE addrs = nullptr;
        if (::GetUnicastIpAddressTable(AF_INET, &addrs) != NO_ERROR || addrs == nullptr) {
            return "";
        }
        std::string ip;
        for (ULONG i = 0; i < addrs->NumEntries; ++i) {
            const MIB_UNICASTIPADDRESS_ROW &a = addrs->Table[i];
            if (a.InterfaceIndex == ifidx) {
                char buf[64] = { 0 };
                ::inet_ntop(AF_INET, &a.Address.Ipv4.sin_addr, buf, sizeof(buf));
                ip = buf;
                break;
            }
        }
        ::FreeMibTable(addrs);
        return ip;
    }

    NET_IFINDEX defaultWinner()
    {
        PMIB_IPFORWARD_TABLE2 table = nullptr;
        if (::GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
            return 0;
        }
        NET_IFINDEX best = 0;
        ULONG bestMetric = ~0UL;
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2 &r = table->Table[i];
            if (r.DestinationPrefix.PrefixLength != 0) {
                continue;
            }
            MIB_IPINTERFACE_ROW iface;
            std::memset(&iface, 0, sizeof(iface));
            iface.Family = AF_INET;
            iface.InterfaceIndex = r.InterfaceIndex;
            ULONG effective = r.Metric;
            if (::GetIpInterfaceEntry(&iface) == NO_ERROR) {
                effective += iface.Metric;
            }
            if (effective < bestMetric) {
                bestMetric = effective;
                best = r.InterfaceIndex;
            }
        }
        ::FreeMibTable(table);
        return best;
    }

    struct PhysAdapter
    {
        HMODULE wintun = nullptr;
        WINTUN_ADAPTER_HANDLE adapter = nullptr;
        WINTUN_SESSION_HANDLE session = nullptr;
        WINTUN_CLOSE_ADAPTER_FUNC *closeAdapter = nullptr;
        WINTUN_END_SESSION_FUNC *endSession = nullptr;
        NET_IFINDEX ifindex = 0;
        bool routeAdded = false;
        bool addrAdded = false;
        MIB_IPFORWARD_ROW2 route {};
        MIB_UNICASTIPADDRESS_ROW addr {};

        bool create()
        {
            wintun = ::LoadLibraryExW(L"wintun.dll", nullptr,
                                      LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (wintun == nullptr) {
                return false;
            }
            auto createAdapter =
                    reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC *>(::GetProcAddress(wintun, "WintunCreateAdapter"));
            closeAdapter = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC *>(::GetProcAddress(wintun, "WintunCloseAdapter"));
            auto getLuid =
                    reinterpret_cast<WINTUN_GET_ADAPTER_LUID_FUNC *>(::GetProcAddress(wintun, "WintunGetAdapterLUID"));
            auto startSession =
                    reinterpret_cast<WINTUN_START_SESSION_FUNC *>(::GetProcAddress(wintun, "WintunStartSession"));
            endSession = reinterpret_cast<WINTUN_END_SESSION_FUNC *>(::GetProcAddress(wintun, "WintunEndSession"));
            if (createAdapter == nullptr || closeAdapter == nullptr || getLuid == nullptr || startSession == nullptr
                || endSession == nullptr) {
                return false;
            }
            adapter = createAdapter(L"xtunphys", L"WireGuard", nullptr);
            if (adapter == nullptr) {
                return false;
            }
            session = startSession(adapter, 0x20000);
            if (session == nullptr) {
                return false;
            }
            NET_LUID luid;
            getLuid(adapter, &luid);
            return ::ConvertInterfaceLuidToIndex(&luid, &ifindex) == NO_ERROR;
        }

        bool addAddress(const char *ip, UINT8 prefix)
        {
            ::InitializeUnicastIpAddressEntry(&addr);
            addr.InterfaceIndex = ifindex;
            addr.Address.Ipv4.sin_family = AF_INET;
            ::inet_pton(AF_INET, ip, &addr.Address.Ipv4.sin_addr);
            addr.OnLinkPrefixLength = prefix;
            addr.DadState = IpDadStatePreferred;
            DWORD rc = ::CreateUnicastIpAddressEntry(&addr);
            addrAdded = rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS;
            return addrAdded;
        }

        bool setLowMetric()
        {
            MIB_IPINTERFACE_ROW row;
            std::memset(&row, 0, sizeof(row));
            row.Family = AF_INET;
            row.InterfaceIndex = ifindex;
            if (::GetIpInterfaceEntry(&row) != NO_ERROR) {
                return false;
            }
            row.UseAutomaticMetric = FALSE;
            row.Metric = 1;
            row.SitePrefixLength = 0;
            return ::SetIpInterfaceEntry(&row) == NO_ERROR;
        }

        bool addDefaultRoute()
        {
            ::InitializeIpForwardEntry(&route);
            route.InterfaceIndex = ifindex;
            route.DestinationPrefix.Prefix.si_family = AF_INET;
            route.DestinationPrefix.PrefixLength = 0;
            route.NextHop.si_family = AF_INET;
            route.Metric = 0;
            DWORD rc = ::CreateIpForwardEntry2(&route);
            routeAdded = rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS;
            return routeAdded;
        }

        ~PhysAdapter()
        {
            if (routeAdded) {
                ::DeleteIpForwardEntry2(&route);
            }
            if (addrAdded) {
                ::DeleteUnicastIpAddressEntry(&addr);
            }
            if (session != nullptr && endSession != nullptr) {
                endSession(session);
            }
            if (adapter != nullptr && closeAdapter != nullptr) {
                closeAdapter(adapter);
            }
            if (wintun != nullptr) {
                ::FreeLibrary(wintun);
            }
        }
    };

} // namespace

TEST(AwgRealTun, DeliversThroughWintunAdapter)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: wintun adapter requires Administrator/SYSTEM";
    }

    WSADATA wsa;
    ASSERT_EQ(::WSAStartup(MAKEWORD(2, 2), &wsa), 0);

    std::string host = localPhysicalIp();
    if (host.empty()) {
        ::WSACleanup();
        GTEST_SKIP() << "no physical default route to host the peer endpoint";
    }

    MemTun tunB;
    libxtun::ClientCallbacks callbacksB {};
    callbacksB.onLog = logB;
    libxtun::proto::Awg b(confB(host));
    b.bind(callbacksB);
    b.setInterface("xtunrtb");
    ASSERT_EQ(b.start(tunB), LIBXTUN_OK);

    libxtun_tunnel_opts opts = realtunOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);

    libxtun::ClientCallbacks callbacksA {};
    callbacksA.onLog = logA;
    libxtun::proto::Awg a(confA("10.9.9.2/32", host));
    a.bind(callbacksA);
    a.setInterface("xtunrta");
    ASSERT_EQ(tunnel.attachProxy(&a), LIBXTUN_OK);
    ASSERT_EQ(tunnel.start(), LIBXTUN_OK);

    a.event(libxtun::ProxyEvent::Up);
    b.event(libxtun::ProxyEvent::Up);

    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(s, INVALID_SOCKET);

    sockaddr_in src {};
    src.sin_family = AF_INET;
    ::inet_pton(AF_INET, "10.9.9.1", &src.sin_addr);
    ASSERT_EQ(::bind(s, reinterpret_cast<sockaddr *>(&src), sizeof(src)), 0)
            << "binding to the tun address requires configureInterface to have assigned it";

    sockaddr_in dst {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9999);
    ::inet_pton(AF_INET, "10.9.9.2", &dst.sin_addr);

    const std::string payload = "xtun-winrealtun-ping";
    std::vector<unsigned char> got;
    bool delivered = false;

    // Long enough for one handshake retransmit: an initiation that reaches a peer
    // which is not running yet is dropped, and RekeyTimeout is 5s.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!delivered && std::chrono::steady_clock::now() < deadline) {
        ::sendto(s, payload.data(), static_cast<int>(payload.size()), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
        if (tunB.awaitDelivery(got, std::chrono::milliseconds(250)) && contains(got, payload)) {
            delivered = true;
        }
    }

    ::closesocket(s);
    tunB.cancel();
    b.stop();

    EXPECT_TRUE(delivered) << "packet did not traverse the wintun tun to peer B";
    ::WSACleanup();
}

TEST(AwgRealTun, RoamRemarkFollowsDefaultRouteChange)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: second wintun adapter + route table require Administrator/SYSTEM";
    }

    WSADATA wsa;
    ASSERT_EQ(::WSAStartup(MAKEWORD(2, 2), &wsa), 0);

    SpyProxy spy;

    libxtun_tunnel_opts opts = realtunOpts();
    libxtun::Tunnel tunnel(opts);
    ASSERT_EQ(tunnel.openTun(), LIBXTUN_OK);
    ASSERT_EQ(tunnel.attachProxy(&spy), LIBXTUN_OK);

    SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(sock, INVALID_SOCKET);
    spy.registerBypass(static_cast<int>(sock), AF_INET);

    NET_IFINDEX before = defaultWinner();
    ASSERT_EQ(boundIfindex(sock), static_cast<unsigned>(before))
            << "registering the socket did not bind it to the current uplink";

    PhysAdapter phys;
    ASSERT_TRUE(phys.create()) << "could not create the simulated physical wintun adapter";
    ASSERT_TRUE(phys.addAddress("10.77.0.1", 24));
    ASSERT_TRUE(phys.setLowMetric());
    ASSERT_TRUE(phys.addDefaultRoute());

    unsigned seen = waitForBinding(sock, phys.ifindex, std::chrono::seconds(3));
    NET_IFINDEX after = defaultWinner();
    bool wonRace = after == phys.ifindex;

    ::closesocket(sock);
    ::WSACleanup();

    if (!wonRace) {
        GTEST_SKIP() << "the simulated adapter (" << phys.ifindex
                     << ") never became the lowest-metric default route (winner=" << after
                     << "); cannot exercise the roam trigger on this host";
    }
    EXPECT_NE(before, phys.ifindex);
    EXPECT_EQ(seen, phys.ifindex)
            << "the default route moved to the new interface but the registered socket was not rebound";
}

#endif
