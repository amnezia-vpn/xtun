#ifndef LIBXTUN_KILLSWITCH_H
#define LIBXTUN_KILLSWITCH_H

#include "util/noncopyable.h"
#include "xtun.h"

#include <memory>
#include <mutex>
#include <string>

namespace libxtun
{
    class Killswitch : private NonCopyable
    {
    public:
        virtual ~Killswitch() = default;

        libxtun_error update(int ifIndex, const std::string &ifName);

        static std::unique_ptr<Killswitch> create(libxtun_killswitch_mode mode, int macosGroup = -1);

    protected:
        Killswitch(libxtun_killswitch_mode mode) noexcept : m_mode(mode)
        {
        }

        [[nodiscard]] bool persistent() const noexcept
        {
            return m_mode == LIBXTUN_KILLSWITCH_MODE_HARD;
        }

        [[nodiscard]] bool installed() const noexcept
        {
            return m_installed;
        }

        virtual libxtun_error install(int ifIndex, const std::string &ifName) = 0;
        virtual void remove() noexcept = 0;

    private:
        libxtun_killswitch_mode m_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        std::mutex m_mutex;
        bool m_installed = false;
    };
}
#endif