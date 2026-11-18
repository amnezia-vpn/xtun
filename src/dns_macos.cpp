#include "dns_macos.h"
#include "net/ip.h"
#include "util/spawn.h"
#include "xtun.h"

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    namespace
    {
        CfRef<CFStringRef> cfString(const std::string &text)
        {
            return CfRef<CFStringRef>(
                    CFStringCreateWithCString(kCFAllocatorDefault, text.c_str(), kCFStringEncodingUTF8));
        }

        CfRef<CFMutableDictionaryRef> cfDictionary()
        {
            return CfRef<CFMutableDictionaryRef>(CFDictionaryCreateMutable(
                    kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
        }

        CfRef<CFMutableArrayRef> cfArray(const std::vector<std::string> &items)
        {
            CfRef<CFMutableArrayRef> array(CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
            for (const std::string &item : items) {
                const CfRef<CFStringRef> text = cfString(item);
                if (!array || !text) {
                    return {};
                }
                CFArrayAppendValue(array.get(), text.get());
            }
            return array;
        }

        std::string serviceKey(const std::string &ifName, const char *entity)
        {
            return "State:/Network/Service/xtun-" + ifName + "/" + entity;
        }
    }

    std::unique_ptr<MacosDns> MacosDns::open(const std::string &ifName)
    {
        CfRef<SCDynamicStoreRef> store(SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("xtun"), nullptr, nullptr));
        if (!store) {
            return nullptr;
        }
        return std::make_unique<MacosDns>(std::move(store), ifName);
    }

    libxtun_error MacosDns::applyResolvers(const std::vector<net::IpAddress> &resolvers)
    {
        revert();

        std::vector<std::string> servers;
        servers.reserve(resolvers.size());
        for (const net::IpAddress &resolver : resolvers) {
            servers.push_back(resolver.toString());
        }

        const CfRef<CFStringRef> ifName = cfString(m_ifName);
        const CfRef<CFMutableArrayRef> serverAddresses = cfArray(servers);
        const CfRef<CFMutableArrayRef> matchDomains = cfArray({ "" });
        const CfRef<CFMutableDictionaryRef> ipv4 = cfDictionary();
        const CfRef<CFMutableDictionaryRef> dns = cfDictionary();
        const CfRef<CFStringRef> ipv4Key = cfString(serviceKey(m_ifName, "IPv4"));
        const CfRef<CFStringRef> dnsKey = cfString(serviceKey(m_ifName, "DNS"));
        if (!ifName || !serverAddresses || !matchDomains || !ipv4 || !dns || !ipv4Key || !dnsKey) {
            return LIBXTUN_ERR_DNS;
        }

        CFDictionarySetValue(ipv4.get(), CFSTR("InterfaceName"), ifName.get());
        CFDictionarySetValue(dns.get(), CFSTR("ServerAddresses"), serverAddresses.get());
        CFDictionarySetValue(dns.get(), CFSTR("SupplementalMatchDomains"), matchDomains.get());

        if (!SCDynamicStoreAddTemporaryValue(m_store.get(), ipv4Key.get(), ipv4.get())
            || !SCDynamicStoreAddTemporaryValue(m_store.get(), dnsKey.get(), dns.get())) {
            revert();
            return LIBXTUN_ERR_DNS;
        }
        flushResolverCache();
        return LIBXTUN_OK;
    }

    void MacosDns::revertResolvers() noexcept
    {
        try {
            for (const char *entity : { "IPv4", "DNS" }) {
                if (const CfRef<CFStringRef> key = cfString(serviceKey(m_ifName, entity))) {
                    SCDynamicStoreRemoveValue(m_store.get(), key.get());
                }
            }
        } catch (...) {
        }
    }

    void MacosDns::flushResolverCache()
    {
        spawn::run("/usr/bin/killall", { "-HUP", "mDNSResponder" }, {});
    }
}
