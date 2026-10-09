#include "killswitch_windows.h"
#include "net/ip.h"
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
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        constexpr const char *POWERSHELL = "powershell -NoProfile -NonInteractive -Command ";
        constexpr const char *SEND_SCRIPT =
                "$c = [System.Net.Sockets.UdpClient]::new($a.AddressFamily); "
                "try { $c.Connect($a, $port); [void]$c.Send($bytes, $bytes.Length); exit 0 } "
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

        std::string byteList(const Nonce &nonce)
        {
            std::ostringstream out;
            for (std::size_t at = 0; at < nonce.size(); ++at) {
                out << (at == 0 ? "" : ",") << std::to_integer<unsigned>(nonce[at]);
            }
            return out.str();
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

        int sendFromPowerShell(const std::string &host, std::uint16_t port, const Nonce &nonce)
        {
            const std::string script = "$a = [System.Net.IPAddress]::Parse('" + host + "'); $port = "
                    + std::to_string(port) + "; $bytes = [byte[]](" + byteList(nonce) + "); " + SEND_SCRIPT;
            return runProcess(POWERSHELL + ("\"" + script + "\""));
        }

        int sendBound(const std::string &host, std::uint16_t port, unsigned long ifIndex, const Nonce &nonce)
        {
            ::addrinfo hints {};
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

            ::addrinfo *resolved = nullptr;
            if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &resolved) != 0) {
                return WSAEINVAL;
            }
            const std::unique_ptr<::addrinfo, decltype(&::freeaddrinfo)> owner(resolved, ::freeaddrinfo);

            const ScopedFd sock(
                    static_cast<int>(::socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol)));
            if (!sock) {
                return ::WSAGetLastError();
            }

            const SOCKET handle = static_cast<SOCKET>(sock.get());
            const bool v6 = resolved->ai_family == AF_INET6;
            const DWORD bound = v6 ? static_cast<DWORD>(ifIndex) : ::htonl(static_cast<u_long>(ifIndex));
            if (::setsockopt(handle, v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_UNICAST_IF : IP_UNICAST_IF,
                             reinterpret_cast<const char *>(&bound), sizeof(bound))
                        != 0
                || ::connect(handle, resolved->ai_addr, static_cast<int>(resolved->ai_addrlen)) != 0
                || ::send(handle, reinterpret_cast<const char *>(nonce.data()), static_cast<int>(nonce.size()), 0)
                        < 0) {
                return ::WSAGetLastError();
            }
            return 0;
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
            "netsh interface ipv4 add route prefix=" + std::string(HIJACKED_PREFIX) + " interface=" + uplinkIndex
                    + " store=active",
            "netsh interface ipv6 add route prefix=" + std::string(TEST_NET_V6_PREFIX) + " interface=" + uplinkIndex
                    + " store=active",
            "netsh interface ipv4 add address name=" + clientIndex + " address=" + CLIENT_SIDE_V4 + " store=active",
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
                    const std::lock_guard<std::mutex> lock(m_mutex);
                    m_uplinkPackets.emplace_back(packet.begin(), packet.begin() + size);
                    m_arrived.notify_all();
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

    SendResult KillswitchEnv::send(const std::string &host, std::uint16_t port, Sender sender, const Nonce &nonce) const
    {
        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            m_uplinkPackets.clear();
        }

        int error = 0;
        switch (sender) {
        case Sender::App: error = sendFromPowerShell(host, port, nonce); break;
        case Sender::Proxy:
            error = sendBound(host, port, static_cast<unsigned long>(m_uplinkTun->ifIndex()), nonce);
            break;
        case Sender::Forwarded: {
            const std::optional<net::IpAddress> destination = net::IpAddress::parse(host);
            if (!destination || destination->family() != AF_INET) {
                ADD_FAILURE() << "forwarded probes are IPv4 only, got " << host;
                return SendResult::Failed;
            }
            const std::vector<std::byte> packet = forwardedPacket(*destination, port, nonce);
            if (m_clientTun->write(packet) != static_cast<int>(packet.size())) {
                ADD_FAILURE() << "could not inject the forwarded probe";
                return SendResult::Failed;
            }
            break;
        }
        }

        if (error == 0) {
            return SendResult::Out;
        }
        if (error == WSAEACCES) {
            return SendResult::Refused;
        }

        ADD_FAILURE() << "the probe to " << host << ' ' << sender << " failed: " << error;
        return SendResult::Failed;
    }

    std::optional<ProbeResult> KillswitchEnv::pollUplink(const Destination &to, const Nonce &nonce) const
    {
        (void)to;

        std::unique_lock<std::mutex> lock(m_mutex);
        m_arrived.wait_for(lock, PROBE_SLICE, [this] { return !m_uplinkPackets.empty(); });
        while (!m_uplinkPackets.empty()) {
            const std::vector<std::byte> packet = std::move(m_uplinkPackets.front());
            m_uplinkPackets.pop_front();
            if (udpPktContainsNonce(packet, nonce)) {
                return ProbeResult::Uplink;
            }
        }
        return std::nullopt;
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::optional<NET_IFINDEX> tunnel = ifindexFromAddr(TUNNEL_ADDRESS);
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
