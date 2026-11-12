#include "killswitch_macos.h"
#include "net/pf.h"
#include "xtun.h"

#include <unistd.h>

#include <cstddef>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    MacosKillswitch::~MacosKillswitch()
    {
        if (installed() && !persistent()) {
            remove();
        }
    }

    libxtun_error MacosKillswitch::install(int ifIndex, const std::string &ifName)
    {
        (void)ifIndex;

        if (ifName.empty()) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        const std::string protectedTable = "<" + std::string(PROTECTED_TABLE) + ">";
        const std::string excludedTable = "<" + std::string(EXCLUDED_TABLE) + ">";
        const std::string dnsTable = "<" + std::string(DNS_TABLE) + ">";

        std::string rules = "table " + protectedTable + " { }\n";
        rules += "table " + excludedTable + " { }\n";
        rules += "table " + dnsTable + " { 0.0.0.0/0, ::/0 }\n";
        rules += "pass out quick on lo0 all no state\n";
        const ::gid_t group = m_group >= 0 ? static_cast<::gid_t>(m_group) : ::getegid();
        rules += "pass out quick all group = " + std::to_string(group) + "\n";
        rules += "pass out quick inet proto udp from any port 68 to any port 67\n";
        rules += "pass out quick inet6 proto udp from any port 546 to any port 547\n";
        rules += "pass out quick inet6 proto ipv6-icmp icmp6-type { 133, 135, 136 }\n";
        rules += "block return out quick proto udp to ! " + dnsTable + " port 53\n";
        rules += "block return out quick proto tcp to ! " + dnsTable + " port { 53 853 }\n";
        rules += "pass out quick on " + ifName + " all no state\n";
        rules += "pass out quick to " + excludedTable + " no state\n";
        rules += "block return out quick to " + protectedTable + "\n";

        if (libxtun_error rc = pf::loadRules(rules, ANCHOR); rc != LIBXTUN_OK) {
            return rc;
        }

        if (libxtun_error rc = pf::enable(m_pfToken); rc != LIBXTUN_OK) {
            pf::flushRules(ANCHOR);
            return rc;
        }

        return LIBXTUN_OK;
    }

    libxtun_error MacosKillswitch::setProtected(const std::vector<net::IpPrefix> &prefixes,
                                                const std::vector<net::IpPrefix> &excludes,
                                                const std::vector<net::IpAddress> &dnsServers)
    {
        const auto replaceTable = [](const char *table, const std::vector<std::string> &entries) {
            std::vector<std::string> args { "-a", ANCHOR, "-t", table, "-T", "replace" };
            args.insert(args.end(), entries.begin(), entries.end());
            const auto result = pf::pfctl(args, {});
            return result ? LIBXTUN_OK : result.error();
        };

        const auto strings = [](const auto &items) {
            std::vector<std::string> out;
            for (const auto &item : items) {
                out.push_back(item.toString());
            }
            return out;
        };

        const std::vector<std::string> allowed =
                prefixes.empty() ? std::vector<std::string> { "0.0.0.0/0", "::/0" } : strings(dnsServers);
        if (const libxtun_error rc = replaceTable(DNS_TABLE, allowed); rc != LIBXTUN_OK) {
            return rc;
        }
        if (const libxtun_error rc = replaceTable(EXCLUDED_TABLE, strings(excludes)); rc != LIBXTUN_OK) {
            return rc;
        }
        return replaceTable(PROTECTED_TABLE, strings(prefixes));
    }

    void MacosKillswitch::remove() noexcept
    {
        try {
            pf::flushRules(ANCHOR);
            if (m_pfToken != 0) {
                pf::disable(std::exchange(m_pfToken, 0));
            }
        } catch (...) {
        }
    }
}
