#include "dns.h"

namespace libxtun
{
    libxtun_error Dns::apply(const std::vector<net::IpAddress> &resolvers)
    {
        if (resolvers == m_appliedResolvers) {
            return LIBXTUN_OK;
        }
        if (resolvers.empty()) {
            revert();
            return LIBXTUN_OK;
        }
        if (libxtun_error err = applyResolvers(resolvers); err != LIBXTUN_OK) {
            m_appliedResolvers.clear();
            return err;
        }
        m_appliedResolvers = resolvers;
        return LIBXTUN_OK;
    }

    void Dns::revert() noexcept
    {
        revertResolvers();
        m_appliedResolvers.clear();
    }
}
