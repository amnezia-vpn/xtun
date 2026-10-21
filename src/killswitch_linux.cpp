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
            const auto block = [&](const char *chain, const char *target) {
                for (const net::IpPrefix &prefix : prefixes) {
                    if (prefix.address().family() == family) {
                        input << "-A " << chain << " -d " << prefix.toString() << " -j " << target << '\n';
                    }
                }
            };

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
            block(CHAIN, "REJECT");
            input << "COMMIT\n"
                  << "*mangle\n"
                  << ':' << FORWARD_CHAIN << " - [0:0]\n"
                  << "-A " << FORWARD_CHAIN << " -o " << ifName << " -j ACCEPT\n";
            block(FORWARD_CHAIN, "DROP");
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
        const std::vector<net::IpPrefix> everything {
            net::IpPrefix(net::IpAddress::fromV4(in_addr {}), 0),
            net::IpPrefix(net::IpAddress::fromV6(in6_addr {}), 0),
        };
        if (const auto rc = setProtected(everything); rc != LIBXTUN_OK) {
            remove();
            return rc;
        }

        for (const int family : { AF_INET, AF_INET6 }) {
            if (iptables::run(family, { "-t", "filter", "-C", "OUTPUT", "-j", CHAIN }) != LIBXTUN_OK
                && iptables::run(family, { "-t", "filter", "-I", "OUTPUT", "1", "-j", CHAIN }) != LIBXTUN_OK) {
                remove();
                return LIBXTUN_ERR_SYSTEM;
            }
            if (iptables::run(family, { "-t", "mangle", "-C", "FORWARD", "-j", FORWARD_CHAIN }) != LIBXTUN_OK
                && iptables::run(family, { "-t", "mangle", "-I", "FORWARD", "1", "-j", FORWARD_CHAIN }) != LIBXTUN_OK) {
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
            iptables::run(family, { "-t", "mangle", "-D", "FORWARD", "-j", FORWARD_CHAIN });
            iptables::run(family, { "-t", "mangle", "-F", FORWARD_CHAIN });
            iptables::run(family, { "-t", "mangle", "-X", FORWARD_CHAIN });
        }
    }
}
