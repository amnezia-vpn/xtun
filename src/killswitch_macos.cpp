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

        std::string rules = "table <" + std::string(PROTECTED_TABLE) + "> {";
        for (const net::IpPrefix &prefix : protectedSet({})) {
            rules += ' ' + prefix.toString();
        }
        rules += " }\n";
        rules += "pass out quick on lo0 all no state\n";
        rules += "pass out quick on " + ifName + " all no state\n";
        rules += "pass out quick inet6 proto ipv6-icmp icmp6-type { 133, 135, 136 }\n";
        const ::gid_t group = m_group >= 0 ? static_cast<::gid_t>(m_group) : ::getegid();
        rules += "pass out quick all group = " + std::to_string(group) + "\n";
        rules += "block return out quick to <" + std::string(PROTECTED_TABLE) + ">\n";

        if (libxtun_error rc = pf::loadRules(rules, ANCHOR); rc != LIBXTUN_OK) {
            return rc;
        }

        if (libxtun_error rc = pf::enable(m_pfToken); rc != LIBXTUN_OK) {
            pf::flushRules(ANCHOR);
            return rc;
        }

        return LIBXTUN_OK;
    }

    libxtun_error MacosKillswitch::setProtected(const std::vector<net::IpPrefix> &prefixes)
    {
        std::vector<std::string> args { "-a", ANCHOR, "-t", PROTECTED_TABLE, "-T", "replace" };
        for (const net::IpPrefix &prefix : prefixes) {
            args.push_back(prefix.toString());
        }
        const auto result = pf::pfctl(args, {});
        return result ? LIBXTUN_OK : result.error();
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
