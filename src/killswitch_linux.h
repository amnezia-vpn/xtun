#ifndef LIBXTUN_KILLSWITCH_LINUX_H
#define LIBXTUN_KILLSWITCH_LINUX_H

#include "killswitch.h"
#include "xtun.h"

namespace libxtun
{
    class LinuxKillswitch final : public Killswitch
    {
    public:
        explicit LinuxKillswitch (libxtun_killswitch_mode mode) noexcept : Killswitch(mode)
        {
        }
        ~LinuxKillswitch() override;

    protected:
        libxtun_error install(int ifIndex, const std::string &ifName) override;
        void remove() noexcept override;

    private:
        libxtun_error updateFallbackRoute(int family, bool add) noexcept;
    };
}
#endif
