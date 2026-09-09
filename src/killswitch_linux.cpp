#include "killswitch_linux.h"
#include "fwmark.h"
#include "net/netlink.h"
#include "xtun.h"

#include <cerrno>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string>
#include <sys/socket.h>

namespace libxtun
{
    LinuxKillswitch::~LinuxKillswitch()
    {
        if (installed() && !persistent()) {
            remove();
        }
    }

    libxtun_error LinuxKillswitch::install(int ifIndex, const std::string &ifName)
    {
        (void)ifIndex;
        (void)ifName;

        for (const int family : { AF_INET, AF_INET6 }) {
            if (const auto rc = updateFallbackRoute(family, true); rc != LIBXTUN_OK) {
                remove();
                return rc;
            }
            // rule duplicating installed by router with higher priority to exclude traffic coming from LAN
            // `priority <RULE_PRIORITY_KILLSWITCH_LAN> from all lookup main suppress_prefixlen 0`
            if (const auto rc = net::netlink::updateRule(true, family, false, 0, RT_TABLE_MAIN,
                                                             0, RULE_PRIORITY_KILLSWITCH_LAN); rc != LIBXTUN_OK) {
                remove();
                return rc;
            }
            // rule before main and after rules added by Router with unreacheable destination
            // `priority <RULE_PRIORITY_KILLSWITCH_TUNNEL> not fwmark <PROXY_FWMARK> lookup <KILLSWITCH_TABLE>`
            if (const auto rc = net::netlink::updateRule(true, family, true, PROXY_FWMARK, KILLSWITCH_TABLE,
                                                             -1, RULE_PRIORITY_KILLSWITCH_TUNNEL); rc != LIBXTUN_OK) {
                remove();
                return rc;
            }
        }

        return LIBXTUN_OK;
    }

    void LinuxKillswitch::remove() noexcept
    {
        for (const int family : { AF_INET, AF_INET6 }) {
            net::netlink::updateRule(false, family, true, PROXY_FWMARK, KILLSWITCH_TABLE,
                    -1, RULE_PRIORITY_KILLSWITCH_TUNNEL);
            net::netlink::updateRule(false, family, false, 0, RT_TABLE_MAIN,
                    0, RULE_PRIORITY_KILLSWITCH_LAN);
            updateFallbackRoute(family, false);
        }
    }

    libxtun_error LinuxKillswitch::updateFallbackRoute(int family, bool add) noexcept
    {
        net::netlink::NetlinkRequest request(add ? RTM_NEWROUTE : RTM_DELROUTE, add ? NLM_F_CREATE | NLM_F_REPLACE : 0,
                                    sizeof(struct rtmsg));

        auto &route = request.payload<struct rtmsg>();
        route.rtm_family = static_cast<unsigned char>(family);
        route.rtm_dst_len = 0;
        route.rtm_table = RT_TABLE_UNSPEC;
        route.rtm_protocol = RTPROT_BOOT;
        route.rtm_scope = RT_SCOPE_UNIVERSE;
        route.rtm_type = RTN_UNREACHABLE;
        request.attribute<std::uint32_t>(RTA_TABLE, KILLSWITCH_TABLE);

        const int rc = request.send();
        return rc == 0 || (add && rc == -EEXIST) ? LIBXTUN_OK : LIBXTUN_ERR_KILLSWITCH;
    }

}
