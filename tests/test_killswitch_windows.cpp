#include "killswitch_windows.h"
#include "net/ip.h"
#include "net/wfp.h"
#include "tun_device.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *POWERSHELL = "powershell -NoProfile -NonInteractive -Command ";
        constexpr const char *CONNECT_SCRIPT =
                "$c = [System.Net.Sockets.TcpClient]::new($a.AddressFamily); "
                "try { if (-not $c.ConnectAsync($a, $port).Wait($ms)) { exit $timedOut }; "
                "if ($c.Client.LocalEndPoint.Address.Equals($tunnel)) { exit $viaTunnel }; exit $elsewhere } "
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

        int connectFromPowerShell(const std::string &host, std::uint16_t port)
        {
            const std::string script = "$a = [System.Net.IPAddress]::Parse('" + host
                    + "'); $port = " + std::to_string(port) + "; $ms = " + std::to_string(PROBE_TIMEOUT.count())
                    + "; $tunnel = [System.Net.IPAddress]::Parse('" + DEFAULT_IFADDR + "'); $viaTunnel = "
                    + std::to_string(CONNECTED_VIA_TUNNEL) + "; $elsewhere = " + std::to_string(CONNECTED_ELSEWHERE)
                    + "; $timedOut = " + std::to_string(WSAETIMEDOUT) + "; " + CONNECT_SCRIPT;
            return runProcess(POWERSHELL + ("\"" + script + "\""));
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

        m_uplinkTun = createTunDevice();
        m_clientTun = createTunDevice();
        if (m_uplinkTun->open() != LIBXTUN_OK || m_clientTun->open() != LIBXTUN_OK) {
            m_skipReason = "could not create the fake uplink and client side adapters";
            return;
        }

        const std::string uplinkIndex = std::to_string(m_uplinkTun->ifIndex());
        const std::string clientIndex = std::to_string(m_clientTun->ifIndex());
        const std::vector<std::string> setup {
            "netsh interface ipv4 set interface " + uplinkIndex + " dadtransmits=0",
            "netsh interface ipv6 set interface " + uplinkIndex + " dadtransmits=0",
            "netsh interface ipv4 set interface " + clientIndex + " dadtransmits=0",
            "netsh interface ipv6 set interface " + clientIndex + " dadtransmits=0",
            "netsh interface ipv4 set interface " + uplinkIndex + " metric=1",
            "netsh interface ipv4 add address name=" + uplinkIndex + " address=" + FAKE_UPLINK_V4 + " store=active",
            "netsh interface ipv6 add address interface=" + uplinkIndex + " address=" + FAKE_UPLINK_V6 + " store=active",
            "netsh interface ipv4 add route prefix=0.0.0.0/0 interface=" + uplinkIndex + " metric=0 store=active",
            "netsh interface ipv4 add route prefix=" + HIJACKED.host + "/32 interface=" + uplinkIndex + " store=active",
            "netsh interface ipv6 add route prefix=" + INTERNET_V6.host + "/128 interface=" + uplinkIndex
                    + " store=active",
            "netsh interface ipv4 add address name=" + clientIndex + " address=" + CLIENT_V4 + " store=active",
            "netsh interface ipv4 set interface " + clientIndex + " forwarding=enabled",
        };
        if (!std::ranges::all_of(setup, [](const std::string &command) { return runProcess(command) == 0; })) {
            m_skipReason = "could not set up the fake uplink and client adapters";
            return;
        }

        m_uplinkReader = std::thread([this] {
            std::array<std::byte, 2048> packet {};
            for (;;) {
                const int size = m_uplinkTun->read(packet);
                if (size == IO_FATAL) {
                    return;
                }
                if (size > 0) {
                    const std::vector<std::byte> reply =
                            handleUplinkPacket(std::span(packet.data(), static_cast<std::size_t>(size)));
                    if (!reply.empty()) {
                        m_uplinkTun->write(reply);
                    }
                }
            }
        });

        m_ifIndex = static_cast<int>(*loopback);
        m_ifName = "xtun";
        cleanup();
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_uplinkReader.joinable()) {
            m_uplinkTun->cancelRead();
            m_uplinkReader.join();
        }
        if (m_ifIndex != 0) {
            cleanup();
        }
        ::WSACleanup();
    }

    int KillswitchEnv::ruleCount() const
    {
        return static_cast<int>(installedFilters().size());
    }

    std::optional<ProbeResult> KillswitchEnv::connect(const std::string &host, std::uint16_t port, Sender sender) const
    {
        int code = 0;
        if (sender == Sender::App) {
            code = connectFromPowerShell(host, port);
        } else {
            const ConnectedSocket tcp =
                    tcpConnect(host, port, PROBE_TIMEOUT, static_cast<unsigned>(m_uplinkTun->ifIndex()));
            code = tcp.error;
            if (code == 0) {
                code = localAddress(tcp.fd) == DEFAULT_IFADDR ? CONNECTED_VIA_TUNNEL : CONNECTED_ELSEWHERE;
            }
        }

        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case WSAEACCES:
        case WSAETIMEDOUT:
        case ETIMEDOUT: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << host << ' ' << sender << " failed: " << code;
        return std::nullopt;
    }

    bool KillswitchEnv::injectSyn(const net::IpAddress &destination, std::uint16_t sport) const
    {
        const std::vector<std::byte> syn = forwardedSyn(destination, sport);
        if (m_clientTun->write(syn) != static_cast<int>(syn.size())) {
            ADD_FAILURE() << "could not inject the forwarded probe";
            return false;
        }
        return true;
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
