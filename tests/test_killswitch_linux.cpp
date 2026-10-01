#include "fwmark.h"
#include "net/netlink.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *UPLINK_DEV = "dummy0";
        constexpr const char *UPLINK_LAN_V4 = "10.10.0.5";
    }

    KillswitchEnv::KillswitchEnv()
    {
        if (!privileged()) {
            m_skipReason = "network namespaces and netlink routing require root";
            return;
        }

        m_netnsFd = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        if (m_netnsFd < 0 || ::unshare(CLONE_NEWNET) != 0) {
            m_skipReason = "could not create a private network namespace";
            return;
        }

        const std::string dev(UPLINK_DEV);
        const std::vector<std::string> setup {
            "ip link set lo up",
            "ip link add " + dev + " type dummy",
            "ip addr add 10.10.0.2/24 dev " + dev,
            "ip -6 addr add " + std::string(IPV6_PATH_ADDRESS) + " dev " + dev + " nodad",
            "ip link set " + dev + " up",
            "ip route add default via 10.10.0.1 dev " + dev,
            "ip -6 route add default via fd00:10::1 dev " + dev,
        };
        if (!std::ranges::all_of(setup, sh)) {
            m_skipReason = "could not set up the dummy uplink: needs the 'dummy' kernel module and IPv6";
            return;
        }
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_netnsFd >= 0) {
            ::setns(m_netnsFd, CLONE_NEWNET);
            ::close(m_netnsFd);
        }
    }

    int KillswitchEnv::ruleCount() const
    {
        int count = 0;
        for (const int family : { AF_INET, AF_INET6 }) {
            count += net::netlink::ruleCount(family, RULE_PRIORITY_KILLSWITCH_TUNNEL);
            count += net::netlink::ruleCount(family, RULE_PRIORITY_KILLSWITCH_LAN);
            count += net::netlink::routeCount(family, KILLSWITCH_TABLE);
        }
        return count;
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const std::string &host, Bypass bypass) const
    {
        const ConnectedSocket udp = udpConnect(host, PROBE_PORT, bypass == Bypass::Proxy ? PROXY_FWMARK : 0);
        if (udp.error == 0) {
            return ProbeResult::Delivered;
        }
        if (udp.error == EHOSTUNREACH || udp.error == ENETUNREACH) {
            return ProbeResult::Blocked;
        }

        ADD_FAILURE() << "the probe failed for an unrelated reason: " << std::strerror(udp.error);
        return std::nullopt;
    }

    using KillswitchLinux = KillswitchTest;

    TEST_F(KillswitchLinux, LanStaysOnLink)
    {
        auto killswitch = m_env.create(LIBXTUN_KILLSWITCH_MODE_HARD);
        ASSERT_NE(killswitch, nullptr);
        expectProbeResult(TEST_NET_V4, Bypass::None, ProbeResult::Blocked);
        expectProbeResult(UPLINK_LAN_V4, Bypass::None, ProbeResult::Delivered);
    }
}
