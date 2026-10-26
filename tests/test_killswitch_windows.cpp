#include "killswitch_windows.h"
#include "net/wfp.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr auto BLOCK_WAIT = std::chrono::milliseconds(200);
        constexpr const char *POWERSHELL = "powershell -NoProfile -NonInteractive -Command ";
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

        std::vector<wfp::FilterInfo> installedFilters()
        {
            auto engine = wfp::WfpEngine::open(makeWfpConfig(false));
            if (!engine) {
                return {};
            }

            auto filters = engine.value()->getInstalledFilters();
            return filters ? std::move(filters).value() : std::vector<wfp::FilterInfo> {};
        }

        void cleanup()
        {
            auto engine = wfp::WfpEngine::open(makeWfpConfig(true));
            if (!engine) {
                ADD_FAILURE() << "could not open a WFP session to clean up the killswitch";
                return;
            }
            if (const libxtun_error rc = engine.value()->cleanup(); rc != LIBXTUN_OK) {
                ADD_FAILURE() << "could not remove the killswitch's WFP objects: " << rc;
            }
        }

        std::optional<unsigned long> bestInterface(const char *host)
        {
            sockaddr_in destination {};
            destination.sin_family = AF_INET;
            if (::inet_pton(AF_INET, host, &destination.sin_addr) != 1) {
                return std::nullopt;
            }

            DWORD index = 0;
            if (::GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&destination), &index) != NO_ERROR) {
                return std::nullopt;
            }
            return index;
        }

        std::optional<NET_IFINDEX> ifindexFromAddr(const char *address)
        {
            in_addr wanted {};
            PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
            if (::inet_pton(AF_INET, address, &wanted) != 1
                || ::GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR) {
                return std::nullopt;
            }

            std::optional<NET_IFINDEX> found;
            for (ULONG entry = 0; entry < table->NumEntries; ++entry) {
                if (table->Table[entry].Address.Ipv4.sin_addr.s_addr == wanted.s_addr) {
                    found = table->Table[entry].InterfaceIndex;
                    break;
                }
            }
            ::FreeMibTable(table);
            return found;
        }

        int runProcess(std::string commandLine)
        {
            SECURITY_ATTRIBUTES inheritable { sizeof(inheritable), nullptr, TRUE };
            const HANDLE nul = ::CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                             &inheritable, OPEN_EXISTING, 0, nullptr);
            STARTUPINFOA startup { sizeof(startup) };
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = startup.hStdOutput = startup.hStdError = nul;
            PROCESS_INFORMATION process {};
            const BOOL started = ::CreateProcessA(nullptr, commandLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                                  nullptr, nullptr, &startup, &process);
            ::CloseHandle(nul);
            if (!started) {
                return -1;
            }
            ::WaitForSingleObject(process.hProcess, INFINITE);
            DWORD code = 1;
            ::GetExitCodeProcess(process.hProcess, &code);
            ::CloseHandle(process.hThread);
            ::CloseHandle(process.hProcess);
            return static_cast<int>(code);
        }

        bool ipv6Route(const char *action, unsigned ifIndex)
        {
            return runProcess(std::string("netsh interface ipv6 ") + action + " route prefix=" + INTERNET_V6.host
                              + "/128 interface=" + std::to_string(ifIndex) + " store=active")
                    == 0;
        }

        int connectFromPowerShell(const std::string &host, std::uint16_t port)
        {
            const std::string script = "$a = [System.Net.IPAddress]::Parse('" + host
                    + "'); $port = " + std::to_string(port) + "; $tunnel = [System.Net.IPAddress]::Parse('"
                    + DEFAULT_IFADDR + "'); $viaTunnel = " + std::to_string(CONNECTED_VIA_TUNNEL) + "; $elsewhere = "
                    + std::to_string(CONNECTED_ELSEWHERE) + "; $ms = " + std::to_string(BLOCK_WAIT.count())
                    + "; $blocked = " + std::to_string(WSAEACCES) + "; " + CONNECT_SCRIPT;
            return runProcess(POWERSHELL + ("\"" + script + "\""));
        }

        int connectFromProxy(const std::string &host, std::uint16_t port, unsigned ifIndex)
        {
            if (tcpConnect(host, port, BLOCK_WAIT, ifIndex).error == WSAEACCES) {
                return WSAEACCES;
            }
            return udpProbe(host, port, ifIndex);
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        WSADATA wsa {};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            m_skipReason = "could not initialize Winsock";
            return;
        }
        if (!privileged()) {
            m_skipReason = "installing WFP filters requires Administrator";
            return;
        }
        if (runProcess(std::string(POWERSHELL) + "exit 0") != 0) {
            m_skipReason = "the app probe needs Windows PowerShell";
            return;
        }

        const std::optional<unsigned long> loopback = bestInterface(LOOPBACK_V4);
        if (!loopback) {
            m_skipReason = "no interface to exempt from the killswitch";
            return;
        }

        const std::optional<unsigned long> uplink = bestInterface(INTERNET_V4.host.c_str());
        if (!uplink) {
            m_skipReason = "no route to " + INTERNET_V4.host;
            return;
        }
        m_uplinkIfIndex = static_cast<unsigned>(*uplink);
        ipv6Route("delete", m_uplinkIfIndex);
        if (!ipv6Route("add", m_uplinkIfIndex)) {
            m_skipReason = "could not route " + INTERNET_V6.host + " through interface " + std::to_string(*uplink)
                    + ", IPv6 may be disabled";
            return;
        }

        m_ifIndex = static_cast<int>(*loopback);
        m_ifName = "xtun";
        cleanup();
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_ifIndex != 0) {
            cleanup();
            ipv6Route("delete", m_uplinkIfIndex);
        }
        ::WSACleanup();
    }

    int KillswitchEnv::ruleCount() const
    {
        return static_cast<int>(installedFilters().size());
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const Destination &to, Sender sender) const
    {
        const int code = sender == Sender::App ? connectFromPowerShell(to.host, PROBE_PORT)
                                               : connectFromProxy(to.host, PROBE_PORT, m_uplinkIfIndex);
        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case WSAEACCES: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << to.host << ' ' << sender << " failed: " << code;
        return std::nullopt;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::optional<NET_IFINDEX> tunnel = ifindexFromAddr(DEFAULT_IFADDR);
        if (!tunnel) {
            return false;
        }

        const std::string index = std::to_string(*tunnel);
        return std::ranges::all_of(routes, [&index](const std::string &route) {
            return runProcess("netsh interface ipv4 delete route prefix=" + route + " interface=" + index
                              + " store=active")
                    == 0;
        });
    }
}
