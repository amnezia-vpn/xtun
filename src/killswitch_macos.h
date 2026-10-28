#ifndef LIBXTUN_KILLSWITCH_MACOS_H
#define LIBXTUN_KILLSWITCH_MACOS_H

#include "killswitch.h"
#include "xtun.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    constexpr const char *ANCHOR = "com.apple/xtun";
    constexpr const char *PROTECTED_TABLE = "xtun_protected";
    constexpr const char *DNS_TABLE = "xtun_dns";

    class MacosKillswitch final : public Killswitch
    {
    public:
        explicit MacosKillswitch (libxtun_killswitch_mode mode, int group,
                                  std::vector<net::IpAddress> dnsExceptions) noexcept
            : Killswitch(mode, std::move(dnsExceptions)), m_group(group)
        {
        }
        ~MacosKillswitch() override;

    protected:
        libxtun_error install(int ifIndex, const std::string &ifName) override;
        libxtun_error setProtected(const std::vector<net::IpPrefix> &prefixes,
                                   const std::vector<net::IpAddress> &dnsServers) override;
        void remove() noexcept override;

    private:
        int m_group = -1;
        std::uint64_t m_pfToken = 0;
    };
}
#endif
