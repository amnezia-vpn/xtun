#include "killswitch_linux.h"
#include "fwmark.h"
#include "net/iptables.h"
#include "xtun.h"

#include <sstream>
#include <string>
#include <vector>

namespace libxtun
{
    namespace
    {
        std::string iptablesRules(int family, const std::string &ifName, const std::vector<net::IpPrefix> &prefixes)
        {
            std::ostringstream input;
            input << "*filter\n"
                  << ':' << CHAIN << " - [0:0]\n"
                  << "-A " << CHAIN << " -o lo -j ACCEPT\n"
                  << "-A " << CHAIN << " -o " << ifName << " -j ACCEPT\n"
                  << "-A " << CHAIN << " -m mark --mark " << std::showbase << std::hex << PROXY_FWMARK << " -j ACCEPT\n";
            if (family == AF_INET6) {
                for (const char *type : { "router-solicitation", "neighbour-solicitation", "neighbour-advertisement" }) {
                    input << "-A " << CHAIN << " -p ipv6-icmp --icmpv6-type " << type << " -j ACCEPT\n";
                }
            }
            for (const net::IpPrefix &prefix : prefixes) {
                if (prefix.address().family() == family) {
                    input << "-A " << CHAIN << " -d " << prefix.toString() << " -j REJECT\n";
                }
            }
            input << "COMMIT\n";
            return input.str();
        }
    }

    LinuxKillswitch::~LinuxKillswitch()
    {
        if (installed() && !persistent()) {
            remove();
        }
    }

    libxtun_error LinuxKillswitch::install(int ifIndex, const std::string &ifName)
    {
        (void)ifIndex;

        m_ifName = ifName;
        if (const auto rc = setProtected(protectedSet({})); rc != LIBXTUN_OK) {
            remove();
            return rc;
        }

        for (const int family : { AF_INET, AF_INET6 }) {
            if (iptables::run(family, { "-t", "filter", "-C", "OUTPUT", "-j", CHAIN }) != LIBXTUN_OK
                && iptables::run(family, { "-t", "filter", "-I", "OUTPUT", "1", "-j", CHAIN }) != LIBXTUN_OK) {
                remove();
                return LIBXTUN_ERR_SYSTEM;
            }
        }

        return LIBXTUN_OK;
    }

    libxtun_error LinuxKillswitch::setProtected(const std::vector<net::IpPrefix> &prefixes)
    {
        for (const int family : { AF_INET, AF_INET6 }) {
            if (const auto rc = iptables::restore(family, iptablesRules(family, m_ifName, prefixes));
                rc != LIBXTUN_OK) {
                return rc;
            }
        }
        return LIBXTUN_OK;
    }

    void LinuxKillswitch::remove() noexcept
    {
        for (const int family : { AF_INET, AF_INET6 }) {
            iptables::run(family, { "-t", "filter", "-D", "OUTPUT", "-j", CHAIN });
            iptables::run(family, { "-t", "filter", "-F", CHAIN });
            iptables::run(family, { "-t", "filter", "-X", CHAIN });
        }
    }
}
