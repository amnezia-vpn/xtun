#include "fwmark.h"
#include "killswitch_linux.h"
#include "net/iptables.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"
#include "util/spawn.h"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *TUN_DEV = "kstun0";

        bool ip(const std::vector<std::string> &args)
        {
            for (const char *path : { "/usr/sbin/ip", "/sbin/ip" }) {
                if (::access(path, X_OK) == 0) {
                    return static_cast<bool>(spawn::run(path, args, {}));
                }
            }
            return false;
        }

        void cleanup()
        {
            Killswitch::create(LIBXTUN_KILLSWITCH_MODE_DISABLED)->update(0, {});
        }

        std::string defaultInterface()
        {
            std::ifstream table("/proc/net/route");
            std::string line;
            std::getline(table, line);
            for (std::string iface, destination; table >> iface >> destination; std::getline(table, line)) {
                if (destination == "00000000") {
                    return iface;
                }
            }
            return {};
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        if (!privileged()) {
            m_skipReason = "iptables requires root";
            return;
        }

        for (const std::string name : { "iptables-restore", "ip6tables-restore" }) {
            if (::access(("/usr/sbin/" + name).c_str(), X_OK) != 0 && ::access(("/sbin/" + name).c_str(), X_OK) != 0) {
                m_skipReason = name + " is missing";
                return;
            }
        }

        const std::string uplink = defaultInterface();
        if (uplink.empty()) {
            m_skipReason = "no IPv4 default route";
            return;
        }
        if (!ip({ "-6", "route", "replace", INTERNET_V6.host, "dev", uplink })) {
            m_skipReason = "could not route " + INTERNET_V6.host + " through " + uplink + ", IPv6 may be disabled";
            return;
        }

        m_ifName = TUN_DEV;
        cleanup();
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_skipReason.empty()) {
            cleanup();
            ip({ "-6", "route", "del", INTERNET_V6.host });
        }
    }

    int KillswitchEnv::ruleCount() const
    {
        const auto chainCount = [](int family, const char *table, const char *builtin, const char *chain) {
            int count = iptables::run(family, { "-t", table, "-C", builtin, "-j", chain }) == LIBXTUN_OK ? 1 : 0;
            const auto rules = iptables::rules(family, table, chain);
            std::istringstream lines(rules ? rules.value() : std::string {});
            for (std::string line; std::getline(lines, line);) {
                if (line.starts_with("-N ") || line.starts_with("-A ")) {
                    ++count;
                }
            }
            return count;
        };

        int count = 0;
        for (const int family : { AF_INET, AF_INET6 }) {
            count += chainCount(family, "filter", "OUTPUT", CHAIN);
        }
        return count;
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const Destination &to, Sender sender, std::uint16_t port) const
    {
        const unsigned mark = sender == Sender::Proxy ? PROXY_FWMARK : 0;
        const int code = port == DNS_TLS_PORT ? tcpProbe(to.host, port, mark) : udpProbe(to.host, port, mark);
        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case EPERM:
        case ECONNREFUSED: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << to.host << ' ' << sender << " failed: " << std::strerror(code);
        return std::nullopt;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::string tunnel = ifnameFromAddr(DEFAULT_IFADDR);
        if (tunnel.empty()) {
            return false;
        }

        return std::ranges::all_of(routes, [&tunnel](const std::string &route) {
            return ip({ "route", "del", route, "dev", tunnel, "table", std::to_string(PROXY_TABLE) });
        });
    }
}
