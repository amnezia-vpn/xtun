#include "killswitch_macos.h"
#include "net/pf.h"
#include "xtun.h"

#include <unistd.h>

#include <cstddef>
#include <cstdlib>
#include <string>
#include <utility>

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

        std::string rules = "pass out quick on lo0 all\n";
        rules += "pass out quick on " + ifName + " all\n";
        rules += "pass out quick inet6 proto ipv6-icmp icmp6-type { 133, 135, 136 }\n";
        rules += "pass out quick all group = " + std::to_string(::getegid()) + "\n";
        rules += "block drop out quick all\n";

        if (libxtun_error rc = pf::loadRules(rules, ANCHOR); rc != LIBXTUN_OK) {
            return rc;
        }

        if (libxtun_error rc = pf::enable(m_pfToken); rc != LIBXTUN_OK) {
            pf::flushRules(ANCHOR);
            return rc;
        }

        return LIBXTUN_OK;
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
