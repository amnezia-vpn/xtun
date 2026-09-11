#include "killswitch.h"
#include "xtun.h"
#include <mutex>

namespace libxtun
{
    libxtun_error Killswitch::update(int ifIndex, const std::string &ifName)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        switch(m_mode) {
        case LIBXTUN_KILLSWITCH_MODE_DISABLED:
            // clear rules installed by HARD
            remove();
            m_installed = false;
            return LIBXTUN_OK;
        case LIBXTUN_KILLSWITCH_MODE_SOFT:
        case LIBXTUN_KILLSWITCH_MODE_HARD:
            if (m_installed) {
                return LIBXTUN_OK;
            }
            auto rc = install(ifIndex, ifName);
            m_installed = rc == LIBXTUN_OK;
            return rc;
        }

        return LIBXTUN_ERR_KILLSWITCH;
    }
}