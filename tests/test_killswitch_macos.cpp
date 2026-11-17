#include "killswitch_macos.h"
#include "net/ip.h"
#include "net/pf.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <unistd.h>

#include <sstream>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *PROBE_IFACE = "utun9";

        std::string anchorRules()
        {
            const auto rules = pf::pfctl({ "-a", ANCHOR, "-s", "rules" }, {});
            return rules ? rules.value() : std::string {};
        }

        std::string protectedEntries()
        {
            const auto entries = pf::pfctl({ "-a", ANCHOR, "-t", PROTECTED_TABLE, "-T", "show" }, {});
            return entries ? entries.value() : std::string {};
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        if (!privileged()) {
            m_skipReason = "loading pf anchors requires root";
            return;
        }

        const auto rules = pf::pfctl({ "-s", "rules" }, {});
        if (!rules || rules.value().find(pf::ANCHOR_REF) == std::string::npos) {
            m_skipReason = "the main pf ruleset does not reference com.apple/*";
            return;
        }

        m_ifName = PROBE_IFACE;
        pf::flushRules(ANCHOR);
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_skipReason.empty()) {
            pf::flushRules(ANCHOR);
        }
    }

    int KillswitchEnv::ruleCount() const
    {
        std::istringstream rules(anchorRules());
        int count = 0;
        for (std::string line; std::getline(rules, line);) {
            if (line.starts_with("pass") || line.starts_with("block")) {
                ++count;
            }
        }

        std::istringstream entries(protectedEntries());
        for (std::string entry; entries >> entry;) {
            if (net::IpPrefix::parse(entry)) {
                ++count;
            }
        }
        return count;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::string tunnel = ifnameFromAddr(DEFAULT_IFADDR);
        if (tunnel.empty()) {
            return false;
        }

        for (const std::string &profileRoute : routes) {
            const std::vector<std::string> prefixes = profileRoute == "0.0.0.0/0"
                    ? std::vector<std::string> { "0.0.0.0/1", "128.0.0.0/1" }
                    : std::vector<std::string> { profileRoute };
            for (const std::string &prefix : prefixes) {
                if (!internal::route({ "-q", "-n", "delete", "-net", prefix, "-interface", tunnel })) {
                    return false;
                }
            }
        }
        return true;
    }

    using KillswitchMacos = KillswitchTest;

    TEST_F(KillswitchMacos, ConfiguredGroupIsExcluded)
    {
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_HARD, static_cast<int>(::getegid()));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);
            ASSERT_EQ(killswitch->protect({ *net::IpPrefix::parse("0.0.0.0/0") }, {}, {}), LIBXTUN_OK);

            expectProbeResult(ROUTED_HOST_V4, Sender::Proxy, ProbeResult::Uplink, "with the process's group");
            expectProbeResult(ROUTED_HOST_V4, Sender::App, ProbeResult::Blocked, "with the process's group");
        }
        {
            const auto killswitch = Killswitch::create(LIBXTUN_KILLSWITCH_MODE_HARD, static_cast<int>(FOREIGN_GID));
            ASSERT_NE(killswitch, nullptr);
            ASSERT_EQ(m_env.update(*killswitch), LIBXTUN_OK);
            ASSERT_EQ(killswitch->protect({ *net::IpPrefix::parse("0.0.0.0/0") }, {}, {}), LIBXTUN_OK);

            expectProbeResult(ROUTED_HOST_V4, Sender::App, ProbeResult::Uplink, "with the foreign group");
            expectProbeResult(ROUTED_HOST_V4, Sender::Proxy, ProbeResult::Blocked, "with the foreign group");
        }
    }
}
