#ifndef LIBXTUN_DNS_MACOS_H
#define LIBXTUN_DNS_MACOS_H

#include "dns.h"
#include "xtun.h"

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace libxtun
{
    struct CfDeleter
    {
        void operator()(CFTypeRef ref) const noexcept
        {
            CFRelease(ref);
        }
    };

    template<typename T> using CfRef = std::unique_ptr<std::remove_pointer_t<T>, CfDeleter>;

    class MacosDns final : public Dns
    {
    public:
        MacosDns(CfRef<SCDynamicStoreRef> store, std::string ifName) noexcept
            : m_store(std::move(store)), m_ifName(std::move(ifName))
        {
        }

        static std::unique_ptr<MacosDns> open(const std::string &ifName);

    protected:
        libxtun_error applyResolvers(const std::vector<net::IpAddress> &resolvers) override;
        void revertResolvers() noexcept override;

    private:
        void flushResolverCache();

        CfRef<SCDynamicStoreRef> m_store;
        std::string m_ifName;
    };
}

#endif // LIBXTUN_DNS_MACOS_H
