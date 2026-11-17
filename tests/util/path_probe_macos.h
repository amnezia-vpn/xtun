#ifndef TEST_PATH_PROBE_MACOS_H
#define TEST_PATH_PROBE_MACOS_H

#include "health/dns_query.h"
#include "os.h"
#include "path_probe.h"
#include "util/spawn.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace libxtun::test
{
    namespace internal
    {
        constexpr const char *UPLINK_ULA = "fd00:7874::2";
        constexpr auto ANSWER_WAIT = std::chrono::milliseconds(1000);

        inline bool ifconfig(const std::vector<std::string> &args)
        {
            return static_cast<bool>(spawn::run("/sbin/ifconfig", args, {}));
        }

        inline bool route(const std::vector<std::string> &args)
        {
            return static_cast<bool>(spawn::run("/sbin/route", args, {}));
        }

        template<typename F> inline int runAsForeignGroup(F &&probe)
        {
            const ::pid_t child = ::fork();
            if (child == 0) {
                ::_exit(::setegid(FOREIGN_GID) != 0 ? errno : probe());
            }
            if (child < 0) {
                return errno;
            }

            int status = 0;
            pid_t r;

            do {
                r = ::waitpid(child, &status, 0);
            } while (r == -1 && errno == EINTR);

            if (r < 0 || !WIFEXITED(status)) {
                return ECHILD;
            }
            return WEXITSTATUS(status);
        }

        inline bool answered(const std::string &host, std::uint16_t port, bool tcp)
        {
            if (tcp) {
                return tcpConnect(host, port, ANSWER_WAIT).error == 0;
            }

            const ConnectedSocket udp = udpConnect(host, port);
            const health::DnsQuery query(0x1234, 0xdeadbeef);
            if (udp.error != 0 || ::send(udp.fd.get(), query.bytes().data(), query.bytes().size(), 0) < 0) {
                return false;
            }
            ::pollfd ready { udp.fd.get(), POLLIN, 0 };
            std::array<std::byte, 512> reply {};
            return ::poll(&ready, 1, static_cast<int>(ANSWER_WAIT.count())) > 0
                    && ::recv(udp.fd.get(), reply.data(), reply.size(), 0) > 0;
        }

        inline std::string defaultInterface()
        {
            const auto output = spawn::run("/sbin/route", { "-n", "get", "default" }, {});
            std::istringstream words(output ? output.value() : std::string {});
            for (std::string word; words >> word;) {
                if (word == "interface:" && words >> word) {
                    return word;
                }
            }
            return {};
        }

        inline bool waitForUla()
        {
            ::sockaddr_in6 ula {};
            ula.sin6_len = sizeof(ula);
            ula.sin6_family = AF_INET6;
            ::inet_pton(AF_INET6, UPLINK_ULA, &ula.sin6_addr);
            const ScopedFd sock(::socket(AF_INET6, SOCK_DGRAM, 0));
            for (int attempt = 0; attempt < 30; ++attempt) {
                if (::bind(sock.get(), reinterpret_cast<const ::sockaddr *>(&ula), sizeof(ula)) == 0) {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            return false;
        }
    }

    inline PathProbe::PathProbe()
    {
        if (!privileged()) {
            m_skipReason = "routing the probes requires root";
            return;
        }
        if (::getegid() == FOREIGN_GID) {
            m_skipReason = "the probe group must differ from the installing group";
            return;
        }

        const std::string uplink = internal::defaultInterface();
        m_uplinkIfIndex = ::if_nametoindex(uplink.c_str());
        if (m_uplinkIfIndex == 0) {
            m_skipReason = "no IPv4 default route";
            return;
        }
        internal::route({ "-q", "-n", "delete", "-inet6", "-host", PROBE_ADDR_V6 });
        if (!internal::route({ "-q", "-n", "add", "-inet6", "-host", PROBE_ADDR_V6, "-interface", uplink })) {
            m_skipReason = "could not route " + PROBE_ADDR_V6 + " through " + uplink + ", IPv6 may be disabled";
            return;
        }
        internal::ifconfig({ uplink, "inet6", internal::UPLINK_ULA, "delete" });
        if (!internal::ifconfig({ uplink, "inet6", std::string(internal::UPLINK_ULA) + "/64", "alias" }) || !internal::waitForUla()) {
            m_skipReason = "could not add a usable " + std::string(internal::UPLINK_ULA) + " to " + uplink;
        }
    }

    inline PathProbe::~PathProbe()
    {
        if (m_skipReason.empty()) {
            internal::route({ "-q", "-n", "delete", "-inet6", "-host", PROBE_ADDR_V6 });
            std::array<char, IF_NAMESIZE> uplink {};
            ::if_indextoname(m_uplinkIfIndex, uplink.data());
            internal::ifconfig({ uplink.data(), "inet6", internal::UPLINK_ULA, "delete" });
        }
    }

    inline std::optional<ProbeResult> PathProbe::probe(const Destination &to, Sender sender, std::uint16_t port) const
    {
        const bool tcp = port == DNS_TLS_PORT;
        const bool dns = tcp || port == DNS_PORT;
        const auto sendProbe = [&](unsigned bypass) {
            const int probeCode = tcp ? tcpProbe(to.host, port, bypass) : udpProbe(to.host, port, bypass);
            if (dns && probeCode == CONNECTED_VIA_TUNNEL && !internal::answered(to.host, port, tcp)) {
                return EPERM;
            }
            return probeCode;
        };
        const int code = sender == Sender::App ? internal::runAsForeignGroup([&] { return sendProbe(0); }) : sendProbe(m_uplinkIfIndex);
        switch (code) {
        case CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
        case CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
        case ECONNREFUSED:
        case EHOSTUNREACH:
        case EINVAL:
        case EPERM: return ProbeResult::Blocked;
        default: break;
        }

        ADD_FAILURE() << "the probe to " << to.host << ' ' << sender << " failed: " << std::strerror(code);
        return std::nullopt;
    }
}

#endif
