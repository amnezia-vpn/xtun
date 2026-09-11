#ifndef LIBXTUN_KILLSWITCH_MACOS_H
#define LIBXTUN_KILLSWITCH_MACOS_H

#include "killswitch.h"
#include "xtun.h"
#include <cstdint>
#include <string>

namespace libxtun
{
    constexpr const char *ANCHOR = "com.apple/xtun";

    class MacosKillswitch final : public Killswitch
    {
    public:
        explicit MacosKillswitch (libxtun_killswitch_mode mode) noexcept : Killswitch(mode)
        {
        }
        ~MacosKillswitch() override;

    protected:
        libxtun_error install(int ifIndex, const std::string &ifName) override;
        void remove() noexcept override;

    private:
        std::uint64_t m_pfToken = 0;
    };
}
#endif
