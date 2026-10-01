#include "killswitch_windows.h"
#include "net/wfp.h"
#include "tun_device.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr auto PROBE_TIMEOUT = std::chrono::milliseconds(100);
        constexpr const char *POWERSHELL = "powershell -NoProfile -NonInteractive -Command ";
        constexpr const char *CONNECT_SCRIPT =
                "$s = [System.Net.Sockets.Socket]::new($a.AddressFamily, 'Stream', 'Tcp'); "
                "$s.Blocking = $false; "
                "try { $s.Connect($a, $port); exit 0 } "
                "catch { $e = $_.Exception; "
                "while ($e -and -not ($e -is [System.Net.Sockets.SocketException])) { $e = $e.InnerException }; "
                "if (-not $e) { exit 1 }; if ($e.ErrorCode -ne 10035) { exit $e.ErrorCode } }; "
                "if ($s.Poll($wait, 'SelectError')) { exit [int]$s.GetSocketOption('Socket', 'Error') }; exit 10035";

        std::vector<wfp::FilterInfo> installedFilters()
        {
            auto engine = wfp::WfpEngine::open(makeWfpConfig(false));
            if (!engine) {
                return {};
            }

            auto filters = engine.value()->getInstalledFilters();
            return filters ? std::move(filters).value() : std::vector<wfp::FilterInfo> {};
        }

        std::optional<NET_IFINDEX> loopbackInterfaceIndex()
        {
            sockaddr_in loopback {};
            loopback.sin_family = AF_INET;
            if (::InetPtonW(AF_INET, L"127.0.0.1", &loopback.sin_addr) != 1) {
                return std::nullopt;
            }

            NET_IFINDEX index = 0;
            if (::GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&loopback), &index) != NO_ERROR) {
                return std::nullopt;
            }
            return index;
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

        int connectInProcess(const std::string &host)
        {
            const ConnectedSocket tcp = tcpConnect(host, PROBE_PORT);
            if (tcp.error != WSAEWOULDBLOCK) {
                return tcp.error;
            }

            fd_set failed;
            FD_ZERO(&failed);
            FD_SET(static_cast<SOCKET>(tcp.fd.get()), &failed);
            timeval timeout { 0, static_cast<long>(std::chrono::microseconds(PROBE_TIMEOUT).count()) };

            const int ready = ::select(0, nullptr, nullptr, &failed, &timeout);
            if (ready == SOCKET_ERROR) {
                return ::WSAGetLastError();
            }
            if (ready == 0) {
                return WSAEWOULDBLOCK;
            }

            int completion = 0;
            int size = sizeof(completion);
            if (::getsockopt(static_cast<SOCKET>(tcp.fd.get()), SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char *>(&completion), &size)
                != 0) {
                return ::WSAGetLastError();
            }
            return completion;
        }

        int connectFromPowerShell(const std::string &host)
        {
            const std::string script = "$a = [System.Net.IPAddress]::Parse('" + host
                    + "'); $port = " + std::to_string(PROBE_PORT) + "; $wait = "
                    + std::to_string(std::chrono::microseconds(PROBE_TIMEOUT).count()) + "; " + CONNECT_SCRIPT;
            return std::system((POWERSHELL + ("\"" + script + "\"")).c_str());
        }

        bool connectAllowed(int error)
        {
            return error == 0 || error == WSAEWOULDBLOCK || error == WSAECONNREFUSED;
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        WSADATA wsa {};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            m_skipReason = "could not initialise Winsock";
            return;
        }
        if (!privileged()) {
            m_skipReason = "installing WFP filters requires Administrator";
            return;
        }
        if (!sh(std::string(POWERSHELL) + "exit 0")) {
            m_skipReason = "the unprotected probe needs Windows PowerShell";
            return;
        }

        if (!connectAllowed(connectInProcess(TEST_NET_V4))) {
            m_skipReason = "no uplink to probe through";
            return;
        }

        const std::optional<NET_IFINDEX> exempt = loopbackInterfaceIndex();
        if (!exempt) {
            m_skipReason = "no interface to exempt from the killswitch";
            return;
        }

        m_ipv6Path = createTunDevice();
        if (m_ipv6Path->open() != LIBXTUN_OK) {
            m_skipReason = "could not create the IPv6 test adapter";
            return;
        }

        const std::string dev = std::to_string(m_ipv6Path->ifIndex());
        const std::vector<std::string> setup {
            "netsh interface ipv6 add address interface=" + dev + " address=" + IPV6_PATH_ADDRESS + " store=active",
            "netsh interface ipv6 add route prefix=" + std::string(TEST_NET_V6_PREFIX) + " interface=" + dev
                    + " store=active",
        };
        if (!std::ranges::all_of(setup, sh)) {
            m_skipReason = "could not route the IPv6 test net into the test adapter";
            return;
        }

        m_ifIndex = static_cast<int>(*exempt);
        m_ifName = "xtun";
        cleanup();
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_ifIndex != 0) {
            cleanup();
        }
        ::WSACleanup();
    }

    int KillswitchEnv::ruleCount() const
    {
        return static_cast<int>(installedFilters().size());
    }

    std::optional<ProbeResult> KillswitchEnv::probe(const std::string &host, Bypass bypass) const
    {
        const int error = bypass == Bypass::Proxy ? connectInProcess(host) : connectFromPowerShell(host);
        if (connectAllowed(error)) {
            return ProbeResult::Delivered;
        }
        if (error == WSAEACCES) {
            return ProbeResult::Blocked;
        }

        ADD_FAILURE() << "the probe failed for an unrelated reason: " << error;
        return std::nullopt;
    }
}
