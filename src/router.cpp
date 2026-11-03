#include "router.h"

namespace libxtun
{
    std::vector<net::IpPrefix> Router::addresses()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        std::vector<net::IpPrefix> result;
        for (const auto &cidr : m_addresses) {
            if (auto prefix = net::IpPrefix::parse(cidr)) {
                result.push_back(*prefix);
            }
        }
        return result;
    }
}
