#include "fwmark.h"
#include "killswitch_linux.h"
#include "net/iptables.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <unistd.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *TUN_DEV = "kstun0";

        void cleanup()
        {
            Killswitch::create(LIBXTUN_KILLSWITCH_MODE_DISABLED)->update(0, {});
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

        m_ifName = TUN_DEV;
        cleanup();
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_skipReason.empty()) {
            cleanup();
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

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::string tunnel = ifnameFromAddr(DEFAULT_IFADDR);
        if (tunnel.empty()) {
            return false;
        }

        return std::ranges::all_of(routes, [&tunnel](const std::string &route) {
            return internal::ip({ "route", "del", route, "dev", tunnel, "table", std::to_string(PROXY_TABLE) });
        });
    }
}
