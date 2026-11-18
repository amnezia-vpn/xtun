#include "dns_windows.h"
#include "net/ip.h"
#include "util/process.h"
#include "util/result.h"
#include "xtun.h"

#include <windows.h>

#include <netioapi.h>
#include <winerror.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace libxtun
{
    namespace
    {
        bool netsh(const std::vector<std::string> &args)
        {
            const ResultXtun<int> result = process::run("netsh.exe", args);
            return result && result.value() == 0;
        }
    }

    std::unique_ptr<WindowsDns> WindowsDns::open(int ifIndex)
    {
        NET_LUID luid {};
        GUID guid {};
        if (ifIndex <= 0 || ::ConvertInterfaceIndexToLuid(static_cast<NET_IFINDEX>(ifIndex), &luid) != NO_ERROR
            || ::ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR) {
            return nullptr;
        }

        const auto setSettings = reinterpret_cast<SetInterfaceDnsSettingsFn>(
                ::GetProcAddress(::GetModuleHandleW(L"iphlpapi.dll"), "SetInterfaceDnsSettings"));
        return std::make_unique<WindowsDns>(ifIndex, guid, setSettings);
    }

    libxtun_error WindowsDns::applyResolvers(const std::vector<net::IpAddress> &resolvers)
    {
        for (const int family : { AF_INET, AF_INET6 }) {
            std::vector<net::IpAddress> servers;
            std::ranges::copy_if(resolvers, std::back_inserter(servers),
                                 [family](const net::IpAddress &resolver) { return resolver.family() == family; });
            if (!setNameServers(family, servers)) {
                revert();
                return LIBXTUN_ERR_DNS;
            }
        }
        flushResolverCache();
        return LIBXTUN_OK;
    }

    void WindowsDns::revertResolvers() noexcept
    {
        try {
            setNameServers(AF_INET, {});
            setNameServers(AF_INET6, {});
        } catch (...) {
        }
    }

    void WindowsDns::flushResolverCache()
    {
        const HMODULE dnsapi = ::LoadLibraryExW(L"dnsapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (dnsapi == nullptr) {
            return;
        }
        if (const auto flush = reinterpret_cast<BOOL(WINAPI *)()>(::GetProcAddress(dnsapi, "DnsFlushResolverCache"))) {
            flush();
        }
        ::FreeLibrary(dnsapi);
    }

    bool WindowsDns::setNameServers(int family, const std::vector<net::IpAddress> &servers)
    {
        if (m_setSettings != nullptr) {
            std::wstring list;
            for (const net::IpAddress &server : servers) {
                const std::string address = server.toString();
                list += (list.empty() ? L"" : L",") + std::wstring(address.begin(), address.end());
            }

            DNS_INTERFACE_SETTINGS settings {};
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
            settings.Flags = DNS_SETTING_NAMESERVER | (family == AF_INET6 ? DNS_SETTING_IPV6 : 0);
            settings.NameServer = list.data();
            return m_setSettings(m_guid, &settings) == NO_ERROR;
        }

        const std::string protocol = family == AF_INET6 ? "ipv6" : "ipv4";
        const std::string name = "name=" + std::to_string(m_ifIndex);
        if (!netsh({ "interface", protocol, "set", "dnsservers", name, "source=static", "address=none",
                     "validate=no" })) {
            return false;
        }
        return std::ranges::all_of(servers, [&](const net::IpAddress &server) {
            return netsh({ "interface", protocol, "add", "dnsservers", name, "address=" + server.toString(),
                           "validate=no" });
        });
    }
}
