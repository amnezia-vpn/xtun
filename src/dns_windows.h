#ifndef LIBXTUN_DNS_WINDOWS_H
#define LIBXTUN_DNS_WINDOWS_H

#include "dns.h"
#include "xtun.h"

#include <winsock2.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <memory>

namespace libxtun
{
    using SetInterfaceDnsSettingsFn = NETIO_STATUS(WINAPI *)(GUID, const DNS_INTERFACE_SETTINGS *);

    class WindowsDns final : public Dns
    {
    public:
        WindowsDns(int ifIndex, const GUID &guid, SetInterfaceDnsSettingsFn setSettings) noexcept
            : m_ifIndex(ifIndex), m_guid(guid), m_setSettings(setSettings)
        {
        }

        static std::unique_ptr<WindowsDns> open(int ifIndex);

        libxtun_error apply(const std::vector<net::IpAddress> &resolvers) override;
        void revert() noexcept override;

    private:
        bool setNameServers(int family, const std::vector<net::IpAddress> &servers);

        int m_ifIndex = 0;
        GUID m_guid {};
        SetInterfaceDnsSettingsFn m_setSettings = nullptr;
    };
}

#endif // LIBXTUN_DNS_WINDOWS_H
