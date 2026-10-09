#ifndef LIBXTUN_KILLSWITCH_LINUX_H
#define LIBXTUN_KILLSWITCH_LINUX_H

#include "killswitch.h"
#include "xtun.h"

#include <string>

namespace libxtun
{
    constexpr const char *CHAIN = "XTUN";
    constexpr const char *FORWARD_CHAIN = "XTUN_FWD";

    class LinuxKillswitch final : public Killswitch
    {
    public:
        explicit LinuxKillswitch (libxtun_killswitch_mode mode) noexcept : Killswitch(mode)
        {
        }
        ~LinuxKillswitch() override;

    protected:
        libxtun_error install(int ifIndex, const std::string &ifName) override;
        libxtun_error setProtected(const std::vector<net::IpPrefix> &prefixes) override;
        void remove() noexcept override;

    private:
        std::string m_ifName;
    };
}
#endif
