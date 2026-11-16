#ifndef LIBXTUN_NET_UPLINK_WINDOWS_H
#define LIBXTUN_NET_UPLINK_WINDOWS_H

#include "net/ip.h"
#include "util/result.h"

namespace libxtun::net
{
    struct WindowsUplink
    {
        unsigned ifIndex = 0;
        IpAddress address;
        IpAddress gateway;
    };

    // Return a usable address of this family, or an empty address if none exists.
    ResultXtun<IpAddress> interfaceAddress(int family, unsigned ifIndex);

    // Choose a connected default route by route + interface metric, skipping the TUN.
    // No usable route gives an empty result with ifIndex == 0.
    ResultXtun<WindowsUplink> defaultUplink(int family, unsigned tunIfIndex);
}

#endif // LIBXTUN_NET_UPLINK_WINDOWS_H
