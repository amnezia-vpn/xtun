#include "router.h"

namespace libxtun
{
    libxtun_error Router::setProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                         const std::vector<net::IpPrefix> &excludes)
    {
        if (routes == m_appliedRoutes && excludes == m_appliedExcludes) {
            return LIBXTUN_OK;
        }
        clearProxyRoutes();
        if (libxtun_error err = addProxyRoutes(routes, excludes); err != LIBXTUN_OK) {
            return err;
        }
        m_appliedRoutes = routes;
        m_appliedExcludes = excludes;
        return LIBXTUN_OK;
    }

    void Router::clearProxyRoutes()
    {
        removeProxyRoutes();
        m_appliedRoutes.clear();
        m_appliedExcludes.clear();
    }
}
