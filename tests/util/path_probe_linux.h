#ifndef TEST_PATH_PROBE_LINUX_H
#define TEST_PATH_PROBE_LINUX_H

#include "fwmark.h"
#include "os.h"
#include "path_probe.h"
#include "util/spawn.h"

#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace internal
    {
        inline bool ip(const std::vector<std::string> &args)
        {
            for (const char *path : { "/usr/sbin/ip", "/sbin/ip" }) {
                if (::access(path, X_OK) == 0) {
                    return static_cast<bool>(spawn::run(path, args, {}));
                }
            }
            return false;
        }

        inline std::string defaultInterface()
        {
            std::ifstream table("/proc/net/route");
            std::string line;
            std::getline(table, line);
            for (std::string iface, destination; table >> iface >> destination; std::getline(table, line)) {
                if (destination == "00000000") {
                    return iface;
                }
            }
            return {};
        }
    }

    inline PathProbe::PathProbe()
    {
        if (!privileged()) {
            m_skipReason = "routing the probes requires root";
            return;
        }

        const std::string uplink = internal::defaultInterface();
        if (uplink.empty()) {
            m_skipReason = "no IPv4 default route";
            return;
        }
        if (!internal::ip({ "-6", "route", "replace", PROBE_ADDR_V6, "dev", uplink })) {
            m_skipReason = "could not route " + PROBE_ADDR_V6 + " through " + uplink + ", IPv6 may be disabled";
        }
    }

    inline PathProbe::~PathProbe()
    {
        if (m_skipReason.empty()) {
            internal::ip({ "-6", "route", "del", PROBE_ADDR_V6 });
        }
    }

    inline std::optional<ProbeResult> PathProbe::probe(const Destination &to, Sender sender, std::uint16_t port) const
    {
        const unsigned mark = sender == Sender::Proxy ? PROXY_FWMARK : 0;
        const int code = port == DNS_TLS_PORT ? tcpProbe(to.host, port, mark) : udpProbe(to.host, port, mark);
        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case EPERM:
        case ECONNREFUSED: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << to.host << ' ' << sender << " failed: " << std::strerror(code);
        return std::nullopt;
    }
}

#endif
