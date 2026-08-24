#include "router_windows.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

bool splitCidr(const std::string &cidr, std::string &ip, int &prefix) {
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

int parseIp(const std::string &ip, int &family, unsigned char out[16]) {
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

void toSockaddrInet(int family, const unsigned char *raw, SOCKADDR_INET &out) {
    std::memset(&out, 0, sizeof(out));
    if (family == AF_INET) {
        out.Ipv4.sin_family = AF_INET;
        std::memcpy(&out.Ipv4.sin_addr, raw, 4);
    } else {
        out.Ipv6.sin6_family = AF_INET6;
        std::memcpy(&out.Ipv6.sin6_addr, raw, 16);
    }
}

}  // namespace

namespace libxtun {

int WindowsRouter::addAddress(const std::string &cidr) {
    std::string ip;
    int prefix;
    if (!splitCidr(cidr, ip, prefix)) {
        return -1;
    }
    int family;
    unsigned char raw[16];
    if (parseIp(ip, family, raw) < 0) {
        return -1;
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
        return 0;
    }
    return -static_cast<int>(rc);
}

int WindowsRouter::removeAddress(const std::string &cidr) {
    std::string ip;
    int prefix;
    if (!splitCidr(cidr, ip, prefix)) {
        return -1;
    }
    int family;
    unsigned char raw[16];
    if (parseIp(ip, family, raw) < 0) {
        return -1;
    }

    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceIndex = static_cast<NET_IFINDEX>(m_ifindex);
    toSockaddrInet(family, raw, row.Address);

    DWORD rc = DeleteUnicastIpAddressEntry(&row);
    if (rc == NO_ERROR || rc == ERROR_NOT_FOUND) {
        return 0;
    }
    return -static_cast<int>(rc);
}

int WindowsRouter::setMtuAndMetric(int family, int mtu) {
    MIB_IPINTERFACE_ROW row;
    std::memset(&row, 0, sizeof(row));
    row.Family = static_cast<ADDRESS_FAMILY>(family);
    row.InterfaceIndex = static_cast<NET_IFINDEX>(m_ifindex);
    DWORD rc = GetIpInterfaceEntry(&row);
    if (rc != NO_ERROR) {
        return -static_cast<int>(rc);
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
        return -static_cast<int>(rc);
    }
    return 0;
}

int WindowsRouter::updateRouteFor(const std::string &cidr, bool add) {
    std::string ip;
    int prefix;
    if (!splitCidr(cidr, ip, prefix)) {
        return -1;
    }
    int family;
    unsigned char raw[16];
    if (parseIp(ip, family, raw) < 0) {
        return -1;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceIndex = static_cast<NET_IFINDEX>(m_ifindex);
    toSockaddrInet(family, raw, row.DestinationPrefix.Prefix);
    row.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix);
    // On-link: an unspecified next hop with the destination's family.
    std::memset(&row.NextHop, 0, sizeof(row.NextHop));
    row.NextHop.si_family = static_cast<ADDRESS_FAMILY>(family);
    row.Metric = 0;

    DWORD rc;
    if (add) {
        rc = CreateIpForwardEntry2(&row);
        if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
            return 0;
        }
    } else {
        rc = DeleteIpForwardEntry2(&row);
        if (rc == NO_ERROR || rc == ERROR_NOT_FOUND) {
            return 0;
        }
    }
    return -static_cast<int>(rc);
}

int WindowsRouter::configureInterface(const std::string &ifname, int ifindex,
                                      const std::vector<std::string> &addresses, int mtu) {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    (void)ifname;  // Windows keys everything on the interface index.
    m_ifindex = static_cast<unsigned long>(ifindex);

    for (const auto &addr : addresses) {
        int rc = addAddress(addr);
        if (rc < 0) {
            revert();
            return rc;
        }
        m_addresses.push_back(addr);
    }

    for (int family : {AF_INET, AF_INET6}) {
        int rc = setMtuAndMetric(family, mtu);
        if (rc < 0) {
            revert();
            return rc;
        }
    }
    return 0;
}

int WindowsRouter::setProxyRoutes(const std::vector<std::string> &routes) {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    // A full tunnel is just 0.0.0.0/0 (and ::/0) via the adapter; the low
    // interface metric set at configure time makes it win. More-specific and
    // split routes are handled identically, and the bypass keeps the proxy's
    // own socket off the tun.
    for (const auto &route : routes) {
        int rc = updateRouteFor(route, true);
        if (rc < 0) {
            clearProxyRoutes();
            return rc;
        }
        m_routes.push_back(route);
    }
    return 0;
}

void WindowsRouter::clearProxyRoutes() {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    for (const auto &route : m_routes) {
        updateRouteFor(route, false);
    }
    m_routes.clear();
}

void WindowsRouter::revert() {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    clearProxyRoutes();
    for (const auto &addr : m_addresses) {
        removeAddress(addr);
    }
    m_addresses.clear();
}

unsigned WindowsRouter::physicalDefaultIfindex() {
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
        return 0;
    }

    unsigned best = 0;
    ULONG bestMetric = ~0UL;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2 &r = table->Table[i];
        if (r.DestinationPrefix.PrefixLength != 0) {
            continue;  // default route only
        }
        if (static_cast<unsigned long>(r.InterfaceIndex) == m_ifindex) {
            continue;  // never bypass onto our own tun
        }
        MIB_IPINTERFACE_ROW iface;
        std::memset(&iface, 0, sizeof(iface));
        iface.Family = AF_INET;
        iface.InterfaceIndex = r.InterfaceIndex;
        ULONG effective = r.Metric;
        if (GetIpInterfaceEntry(&iface) == NO_ERROR) {
            effective += iface.Metric;
        }
        if (effective < bestMetric) {
            bestMetric = effective;
            best = r.InterfaceIndex;
        }
    }

    FreeMibTable(table);
    return best;
}

int WindowsRouter::bypassSocket(int fd, int family) {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    const unsigned idx = physicalDefaultIfindex();
    if (idx == 0) {
        return -1;
    }
    m_bypassIfindex = idx;

    SOCKET s = static_cast<SOCKET>(fd);
    if (family == AF_INET6) {
        DWORD scope = idx;
        return ::setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF,
                            reinterpret_cast<const char *>(&scope), sizeof(scope)) == 0 ? 0 : -1;
    }
    DWORD scope = ::htonl(idx);
    return ::setsockopt(s, IPPROTO_IP, IP_UNICAST_IF,
                        reinterpret_cast<const char *>(&scope), sizeof(scope)) == 0 ? 0 : -1;
}

bool WindowsRouter::bypassChanged() {
    std::lock_guard<std::recursive_mutex> lock(m_mtx);
    const unsigned idx = physicalDefaultIfindex();
    if (idx == 0 || idx == m_bypassIfindex) {
        return false;
    }
    m_bypassIfindex = idx;
    return true;
}

}
