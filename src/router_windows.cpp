#include "router_windows.h"
#include "xtun.h"

#include <winsock2.h>
#include <ws2tcpip.h>

// iphlpapi.h MUST NOT be included before winsock2.h to avoid redefinition errors.
#include <iphlpapi.h>

#include <cstdlib>
#include <cstring>
#include <vector>

namespace
{
    bool splitCidr(const std::string &cidr, std::string &ip, int &prefix)
    {
        auto slash = cidr.find('/');
        if (slash == std::string::npos) {
            ip = cidr;
            prefix = cidr.find(':') != std::string::npos ? 128 : 32;
        } else {
            ip = cidr.substr(0, slash);
            prefix = std::atoi(cidr.c_str() + slash + 1);
        }
        return !ip.empty();
    }

    int parseIp(const std::string &ip, int &family, unsigned char out[16])
    {
        if (inet_pton(AF_INET, ip.c_str(), out) == 1) {
            family = AF_INET;
            return 4;
        }
        if (inet_pton(AF_INET6, ip.c_str(), out) == 1) {
            family = AF_INET6;
            return 16;
        }
        return -1;
    }

    void toSockaddrInet(int family, const unsigned char *raw, SOCKADDR_INET &out)
    {
        std::memset(&out, 0, sizeof(out));
        if (family == AF_INET) {
            out.Ipv4.sin_family = AF_INET;
            std::memcpy(&out.Ipv4.sin_addr, raw, 4);
        } else {
            out.Ipv6.sin6_family = AF_INET6;
            std::memcpy(&out.Ipv6.sin6_addr, raw, 16);
        }
    }
} // namespace

namespace libxtun
{
    libxtun_error WindowsRouter::addAddress(const std::string &cidr)
    {
        std::string ip;
        int prefix;
        if (!splitCidr(cidr, ip, prefix)) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        int family;
        unsigned char raw[16];
        if (parseIp(ip, family, raw) < 0) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceIndex = static_cast<NET_IFINDEX>(m_ifindex);
        toSockaddrInet(family, raw, row.Address);
        row.OnLinkPrefixLength = static_cast<UINT8>(prefix);
        // Skip duplicate-address detection: the tun's address is ours alone.
        row.DadState = IpDadStatePreferred;

        DWORD rc = CreateUnicastIpAddressEntry(&row);
        if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
            return LIBXTUN_OK;
        }
        return LIBXTUN_ERR_SYSTEM;
    }

    libxtun_error WindowsRouter::removeAddress(const std::string &cidr)
    {
        std::string ip;
        int prefix;
        if (!splitCidr(cidr, ip, prefix)) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        int family;
        unsigned char raw[16];
        if (parseIp(ip, family, raw) < 0) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceIndex = static_cast<NET_IFINDEX>(m_ifindex);
        toSockaddrInet(family, raw, row.Address);

        DWORD rc = DeleteUnicastIpAddressEntry(&row);
        if (rc == NO_ERROR || rc == ERROR_NOT_FOUND) {
            return LIBXTUN_OK;
        }
        return LIBXTUN_ERR_SYSTEM;
    }

    libxtun_error WindowsRouter::setMtuAndMetric(int family, int mtu)
    {
        MIB_IPINTERFACE_ROW row;
        std::memset(&row, 0, sizeof(row));
        row.Family = static_cast<ADDRESS_FAMILY>(family);
        row.InterfaceIndex = static_cast<NET_IFINDEX>(m_ifindex);
        DWORD rc = GetIpInterfaceEntry(&row);
        if (rc != NO_ERROR) {
            return LIBXTUN_ERR_SYSTEM;
        }

        if (mtu > 0) {
            row.NlMtu = static_cast<ULONG>(mtu);
        }
        // A metric of 0 with automatic metrics off gives the tun the lowest route
        // metric, so its default route wins over the physical uplink's.
        row.Metric = 0;
        row.UseAutomaticMetric = FALSE;
        // SetIpInterfaceEntry rejects the IPv4 SitePrefixLength that Get returns.
        if (family == AF_INET) {
            row.SitePrefixLength = 0;
        }

        rc = SetIpInterfaceEntry(&row);
        if (rc != NO_ERROR) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error WindowsRouter::updateRouteFor(const net::IpPrefix &prefix, bool add, const net::WindowsUplink *uplink)
    {
        const int family = prefix.address().family();
        const auto octets = prefix.address().octets();

        MIB_IPFORWARD_ROW2 row;
        InitializeIpForwardEntry(&row);
        row.InterfaceIndex = uplink != nullptr ? uplink->ifIndex : static_cast<NET_IFINDEX>(m_ifindex);
        toSockaddrInet(family, reinterpret_cast<const unsigned char *>(octets.data()), row.DestinationPrefix.Prefix);
        row.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix.bits());
        if (uplink != nullptr) {
            toSockaddrInet(family, reinterpret_cast<const unsigned char *>(uplink->gateway.octets().data()), row.NextHop);
        } else {
            // On-link: an unspecified next hop with the destination's family.
            std::memset(&row.NextHop, 0, sizeof(row.NextHop));
            row.NextHop.si_family = static_cast<ADDRESS_FAMILY>(family);
        }
        row.Metric = 0;

        DWORD rc;
        if (add) {
            rc = CreateIpForwardEntry2(&row);
            if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
                return LIBXTUN_OK;
            }
        } else {
            rc = DeleteIpForwardEntry2(&row);
            if (rc == NO_ERROR || rc == ERROR_NOT_FOUND) {
                return LIBXTUN_OK;
            }
        }
        return LIBXTUN_ERR_SYSTEM;
    }

    libxtun_error WindowsRouter::updateUplinkRoutes(int family, const net::WindowsUplink &uplink, bool add)
    {
        if (uplink.ifIndex == 0) {
            return LIBXTUN_OK;
        }

        for (const net::IpPrefix &exclude : m_excludes) {
            if (exclude.address().family() != family) {
                continue;
            }
            if (libxtun_error err = updateRouteFor(exclude, add, &uplink); add && err != LIBXTUN_OK) {
                updateUplinkRoutes(family, uplink, false);
                return err;
            }
        }
        return LIBXTUN_OK;
    }

    libxtun_error WindowsRouter::configureInterface(const std::string &ifname, int ifindex,
                                                    const std::vector<std::string> &addresses, int mtu)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        (void)ifname; // Windows keys everything on the interface index.
        m_ifindex = static_cast<unsigned long>(ifindex);
        if (const auto uplink = net::defaultUplink(AF_INET, m_ifindex)) {
            m_uplinkV4 = uplink.value();
        }
        if (const auto uplink = net::defaultUplink(AF_INET6, m_ifindex)) {
            m_uplinkV6 = uplink.value();
        }

        for (const auto &addr : addresses) {
            auto rc = addAddress(addr);
            if (rc < 0) {
                revert();
                return rc;
            }
            m_addresses.push_back(addr);
        }

        for (int family : { AF_INET, AF_INET6 }) {
            auto rc = setMtuAndMetric(family, mtu);
            if (rc < 0) {
                revert();
                return rc;
            }
        }
        return LIBXTUN_OK;
    }

    libxtun_error WindowsRouter::addProxyRoutes(const std::vector<net::IpPrefix> &routes,
                                                const std::vector<net::IpPrefix> &excludes)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        // A full tunnel is just 0.0.0.0/0 (and ::/0) via the adapter; the low
        // interface metric set at configure time makes it win. More-specific and
        // split routes are handled identically, and the bypass keeps the proxy's
        // own socket off the tun.
        for (const auto &route : routes) {
            auto rc = updateRouteFor(route, true);
            if (rc < 0) {
                clearProxyRoutes();
                return rc;
            }
            m_routes.push_back(route);
        }

        m_excludes = excludes;
        for (const int family : { AF_INET, AF_INET6 }) {
            if (libxtun_error err = updateUplinkRoutes(family, family == AF_INET ? m_uplinkV4 : m_uplinkV6, true);
                err != LIBXTUN_OK) {
                clearProxyRoutes();
                return err;
            }
        }
        return LIBXTUN_OK;
    }

    void WindowsRouter::removeProxyRoutes()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        for (const int family : { AF_INET, AF_INET6 }) {
            updateUplinkRoutes(family, family == AF_INET ? m_uplinkV4 : m_uplinkV6, false);
        }
        m_excludes.clear();
        for (const auto &route : m_routes) {
            updateRouteFor(route, false);
        }
        m_routes.clear();
    }

    void WindowsRouter::revert()
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        clearProxyRoutes();
        for (const auto &addr : m_addresses) {
            removeAddress(addr);
        }
        m_addresses.clear();
    }

    void WindowsRouter::onRouteChanged()
    {
        {
            std::lock_guard<std::recursive_mutex> lock(m_mtx);
            bool uplinkChanged = false;
            for (const int family : { AF_INET, AF_INET6 }) {
                net::WindowsUplink &previous = family == AF_INET ? m_uplinkV4 : m_uplinkV6;
                const auto current = net::defaultUplink(family, m_ifindex);
                if (!current) {
                    continue;
                }
                if (current.value().ifIndex == previous.ifIndex && current.value().gateway == previous.gateway) {
                    continue;
                }
                updateUplinkRoutes(family, previous, false);
                previous = current.value();
                uplinkChanged = true;
            }
            if (!uplinkChanged) {
                return;
            }
            if (updateUplinkRoutes(AF_INET, m_uplinkV4, true) != LIBXTUN_OK ||
                updateUplinkRoutes(AF_INET6, m_uplinkV6, true) != LIBXTUN_OK) {
                updateUplinkRoutes(AF_INET, m_uplinkV4, false);
                updateUplinkRoutes(AF_INET6, m_uplinkV6, false);
            }
        }
        m_listener.onUplinkChanged();
    }

    void WindowsRouter::protectSocket(int fd)
    {
        std::lock_guard<std::recursive_mutex> lock(m_mtx);
        SOCKET s = static_cast<SOCKET>(fd);

        if (m_uplinkV4.ifIndex != 0) {
            const DWORD val = ::htonl(m_uplinkV4.ifIndex); // IP_UNICAST_IF expects index in network byte order
            ::setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char *>(&val), sizeof(val));
        }
        if (m_uplinkV6.ifIndex != 0) {
            const DWORD val = m_uplinkV6.ifIndex;
            ::setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<const char *>(&val), sizeof(val));
        }
    }
}
