#ifndef LIBXTUN_KILLSWITCH_LINUX_H
#define LIBXTUN_KILLSWITCH_LINUX_H

#include "killswitch.h"
#include "xtun.h"

#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    constexpr const char *CHAIN = "XTUN";
    constexpr const char *DNS_CHAIN = "XTUN_DNS";

    class LinuxKillswitch final : public Killswitch
    {
    public:
        explicit LinuxKillswitch (libxtun_killswitch_mode mode, std::vector<net::IpAddress> dnsExceptions) noexcept
            : Killswitch(mode, std::move(dnsExceptions))
        {
        }
        ~LinuxKillswitch() override;

    protected:
        libxtun_error install(int ifIndex, const std::string &ifName) override;
        libxtun_error setProtected(const std::vector<net::IpPrefix> &prefixes,
                                   const std::vector<net::IpPrefix> &excludes,
                                   const std::vector<net::IpAddress> &dnsServers) override;
        void remove() noexcept override;

    private:
        std::string m_ifName;
        std::vector<net::IpPrefix> m_prefixes;
        std::vector<net::IpPrefix> m_excludes;
        std::vector<net::IpAddress> m_dnsServers;
    };
}
#endif
