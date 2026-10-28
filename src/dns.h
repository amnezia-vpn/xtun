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

        virtual libxtun_error apply(const std::vector<net::IpAddress> &resolvers) = 0; // empty -> revert()
        virtual void revert() noexcept = 0;

        static std::unique_ptr<Dns> create(int ifIndex, const std::string &ifName);
    };
}

#endif // LIBXTUN_DNS_H
