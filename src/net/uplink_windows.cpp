#include "uplink_windows.h"

#include <iphlpapi.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace libxtun::net
{
    ResultXtun<IpAddress> interfaceAddress(int family, unsigned ifIndex)
    {
        if ((family != AF_INET && family != AF_INET6) || ifIndex == 0) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }

        MIB_UNICASTIPADDRESS_TABLE *rawTable = nullptr;
        if (::GetUnicastIpAddressTable(AF_UNSPEC, &rawTable) != NO_ERROR) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        const std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&::FreeMibTable)> table(rawTable, &::FreeMibTable);
        IpAddress selected;

        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto &row = table->Table[i];
            if (row.InterfaceIndex != ifIndex || row.Address.si_family != family || row.SkipAsSource
                || row.DadState != IpDadStatePreferred || row.ValidLifetime == 0) {
                continue;
            }

            IpAddress address;
            if (family == AF_INET) {
                const auto value = ::ntohl(row.Address.Ipv4.sin_addr.s_addr);
                // Skip unspecified, loopback, link-local, multicast, and reserved addresses.
                if (value == 0 || (value >> 24) == 127 || (value >> 16) == 0xa9fe || (value >> 28) >= 14) {
                    continue;
                }
                address = IpAddress::fromV4(row.Address.Ipv4.sin_addr);
            } else {
                const auto &value = row.Address.Ipv6.sin6_addr;
                if (IN6_IS_ADDR_UNSPECIFIED(&value) || IN6_IS_ADDR_LOOPBACK(&value) || IN6_IS_ADDR_LINKLOCAL(&value)
                    || IN6_IS_ADDR_MULTICAST(&value)) {
                    continue;
                }
                address = IpAddress::fromV6(value);
            }

            // The table order is not documented.
            // Pick the smallest address, so the same addresses always give the same choice.
            if (!selected.valid()
                || std::lexicographical_compare(address.octets().begin(), address.octets().end(),
                                                selected.octets().begin(), selected.octets().end())) {
                selected = address;
            }
        }
        return selected;
    }

    ResultXtun<WindowsUplink> defaultUplink(int family, unsigned tunIfIndex)
    {
        if (family != AF_INET && family != AF_INET6) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }

        MIB_IPFORWARD_TABLE2 *rawTable = nullptr;
        if (::GetIpForwardTable2(AF_UNSPEC, &rawTable) != NO_ERROR) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        const std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&::FreeMibTable)> table(rawTable, &::FreeMibTable);
        WindowsUplink selected;
        auto bestMetric = std::numeric_limits<std::uint64_t>::max();

        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto &route = table->Table[i];

            if (route.DestinationPrefix.Prefix.si_family != family || route.DestinationPrefix.PrefixLength != 0
                || route.InterfaceIndex == tunIfIndex || route.ValidLifetime == 0 || route.Loopback) {
                continue;
            }

            MIB_IPINTERFACE_ROW ipInterface {};
            ipInterface.Family = static_cast<ADDRESS_FAMILY>(family);
            ipInterface.InterfaceIndex = route.InterfaceIndex;
            const auto ipError = ::GetIpInterfaceEntry(&ipInterface);

            if (ipError == ERROR_NOT_FOUND || ipError == ERROR_FILE_NOT_FOUND) {
                continue;
            }
            if (ipError != NO_ERROR) {
                return fail(LIBXTUN_ERR_SYSTEM);
            }
            if (!ipInterface.Connected) {
                continue;
            }

            MIB_IF_ROW2 adapter {};
            adapter.InterfaceIndex = route.InterfaceIndex;
            const auto adapterError = ::GetIfEntry2(&adapter);

            if (adapterError == ERROR_FILE_NOT_FOUND) {
                continue;
            }
            if (adapterError != NO_ERROR) {
                return fail(LIBXTUN_ERR_SYSTEM);
            }
            if (adapter.OperStatus != IfOperStatusUp || adapter.Type == IF_TYPE_SOFTWARE_LOOPBACK) {
                continue;
            }
            const auto metric = static_cast<std::uint64_t>(route.Metric) + ipInterface.Metric;
            if (metric > bestMetric || (metric == bestMetric && route.InterfaceIndex >= selected.ifIndex)) {
                continue;
            }
            auto address = interfaceAddress(family, route.InterfaceIndex);
            if (!address) {
                return fail(address.error());
            }
            if (!address.value().valid()) {
                continue;
            }
            const IpAddress gateway = family == AF_INET ? IpAddress::fromV4(route.NextHop.Ipv4.sin_addr)
                                                        : IpAddress::fromV6(route.NextHop.Ipv6.sin6_addr);
            selected = { route.InterfaceIndex, std::move(address).value(), gateway };
            bestMetric = metric;
        }
        return selected;
    }
}
