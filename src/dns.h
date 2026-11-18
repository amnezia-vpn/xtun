#ifndef LIBXTUN_DNS_H
#define LIBXTUN_DNS_H

#include "net/ip.h"
#include "util/noncopyable.h"
#include "xtun.h"

#include <memory>
#include <string>
#include <vector>

namespace libxtun
{
    class Dns : private NonCopyable
    {
    public:
        virtual ~Dns() = default;

        libxtun_error apply(const std::vector<net::IpAddress> &resolvers);
        void revert() noexcept;

        static std::unique_ptr<Dns> create(int ifIndex, const std::string &ifName);

    protected:
        virtual libxtun_error applyResolvers(const std::vector<net::IpAddress> &resolvers) = 0;
        virtual void revertResolvers() noexcept = 0;

    private:
        std::vector<net::IpAddress> m_appliedResolvers;
    };
}

#endif // LIBXTUN_DNS_H
