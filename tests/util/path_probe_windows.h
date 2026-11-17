#ifndef TEST_PATH_PROBE_WINDOWS_H
#define TEST_PATH_PROBE_WINDOWS_H

#include "config.h"
#include "os.h"
#include "path_probe.h"
#include "util/process.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace internal
    {
        constexpr auto BLOCK_WAIT = std::chrono::milliseconds(200);
        constexpr const char *POWERSHELL = "WindowsPowerShell\\v1.0\\powershell.exe";
        constexpr const char *CONNECT_SCRIPT =
                "$c = [System.Net.Sockets.UdpClient]::new($a.AddressFamily); "
                "$t = [System.Net.Sockets.TcpClient]::new($a.AddressFamily); "
                "try { $c.Connect($a, $port); $local = $c.Client.LocalEndPoint.Address; "
                "try { [void]$t.ConnectAsync($a, $port).Wait($ms) } "
                "catch { if ($_.Exception.GetBaseException().ErrorCode -eq $blocked) { exit $blocked } }; "
                "if ($local.Equals($tunnel)) { exit $viaTunnel }; exit $elsewhere } "
                "catch { $e = $_.Exception; "
                "while ($e -and -not ($e -is [System.Net.Sockets.SocketException])) { $e = $e.InnerException }; "
                "if (-not $e) { exit 1 }; exit $e.ErrorCode }";

        inline bool netsh(const std::vector<std::string> &args)
        {
            const ResultXtun<int> result = process::run("netsh.exe", args);
            return result && result.value() == 0;
        }

        inline int powershell(const std::string &script)
        {
            const ResultXtun<int> result =
                    process::run(POWERSHELL, { "-NoProfile", "-NonInteractive", "-Command", script });
            return result ? result.value() : -1;
        }

        inline bool ipv6Route(const char *action, unsigned ifIndex)
        {
            return netsh({ "interface", "ipv6", action, "route", std::string("prefix=") + PROBE_ADDR_V6 + "/128",
                           "interface=" + std::to_string(ifIndex), "store=active" });
        }

        inline int connectFromPowerShell(const std::string &host, std::uint16_t port)
        {
            const std::string script = "$a = [System.Net.IPAddress]::Parse('" + host
                    + "'); $port = " + std::to_string(port) + "; $tunnel = [System.Net.IPAddress]::Parse('"
                    + DEFAULT_IFADDR + "'); $viaTunnel = " + std::to_string(CONNECTED_VIA_TUNNEL) + "; $elsewhere = "
                    + std::to_string(CONNECTED_ELSEWHERE) + "; $ms = " + std::to_string(BLOCK_WAIT.count())
                    + "; $blocked = " + std::to_string(WSAEACCES) + "; " + CONNECT_SCRIPT;
            return powershell(script);
        }

        inline int connectFromProxy(const std::string &host, std::uint16_t port, unsigned ifIndex)
        {
            if (tcpConnect(host, port, BLOCK_WAIT, ifIndex).error == WSAEACCES) {
                return WSAEACCES;
            }
            return udpProbe(host, port, ifIndex);
        }
    }

    inline PathProbe::PathProbe()
    {
        WSADATA wsa {};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            m_skipReason = "could not initialize Winsock";
            return;
        }
        if (!privileged()) {
            m_skipReason = "routing the probes requires Administrator";
            return;
        }
        if (internal::powershell("exit 0") != 0) {
            m_skipReason = "the app probe needs Windows PowerShell";
            return;
        }

        const std::optional<unsigned long> uplink = bestInterface(probeAddress(0).c_str());
        if (!uplink) {
            m_skipReason = "no route to " + probeAddress(0);
            return;
        }
        m_uplinkIfIndex = static_cast<unsigned>(*uplink);
        internal::ipv6Route("delete", m_uplinkIfIndex);
        if (!internal::ipv6Route("add", m_uplinkIfIndex)) {
            m_skipReason = "could not route " + PROBE_ADDR_V6 + " through interface " + std::to_string(*uplink)
                    + ", IPv6 may be disabled";
        }
    }

    inline PathProbe::~PathProbe()
    {
        if (m_skipReason.empty()) {
            internal::ipv6Route("delete", m_uplinkIfIndex);
        }
        ::WSACleanup();
    }

    inline std::optional<ProbeResult> PathProbe::probe(const Destination &to, Sender sender, std::uint16_t port) const
    {
        const int code = sender == Sender::App ? internal::connectFromPowerShell(to.host, port)
                                               : internal::connectFromProxy(to.host, port, m_uplinkIfIndex);
        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case WSAEACCES: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << to.host << ' ' << sender << " failed: " << code;
        return std::nullopt;
    }
}

#endif
