#ifndef LIBXTUN_DNS_MACOS_H
#define LIBXTUN_DNS_MACOS_H

#include "dns.h"
#include "util/noncopyable.h"
#include "xtun.h"

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <memory>
#include <string>
#include <utility>

namespace libxtun
{
    template<typename T> class CfRef final : private NonCopyable
    {
    public:
        CfRef() noexcept = default;
        explicit CfRef(T ref) noexcept : m_ref(ref)
        {
        }
        CfRef(CfRef &&other) noexcept : m_ref(std::exchange(other.m_ref, nullptr))
        {
        }
        ~CfRef()
        {
            if (m_ref != nullptr) {
                CFRelease(m_ref);
            }
        }

        [[nodiscard]] T get() const noexcept
        {
            return m_ref;
        }
        explicit operator bool() const noexcept
        {
            return m_ref != nullptr;
        }

    private:
        T m_ref = nullptr;
    };

    class MacosDns final : public Dns
    {
    public:
        MacosDns(CfRef<SCDynamicStoreRef> store, std::string ifName) noexcept
            : m_store(std::move(store)), m_ifName(std::move(ifName))
        {
        }

        static std::unique_ptr<MacosDns> open(const std::string &ifName);

        libxtun_error apply(const std::vector<net::IpAddress> &resolvers) override;
        void revert() noexcept override;

    private:
        void flushResolverCache();

        CfRef<SCDynamicStoreRef> m_store;
        std::string m_ifName;
    };
}

#endif // LIBXTUN_DNS_MACOS_H
