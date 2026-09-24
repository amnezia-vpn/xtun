#include "awg.h"
#include "awg_conf.h"
#include "io/remapping_io.h"
#include "net/ip.h"
#include "proxy.h"
#include "tunnel_io.h"
#include "xtun.h"

#include <cstring>
#include <libgoxtun.h>

#include <memory>

#if defined(_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif

namespace
{
    enum TunEvent {
        TunEventUp = 1,
        TunEventDown = 2,
        TunEventMtuUpdate = 4,
    };
}

namespace libxtun
{
    namespace proto
    {
        Awg::Awg(ClientCallbacks callbacks, awg::Config conf) : Proxy(callbacks), m_conf(std::move(conf))
        {
        }

        Awg::~Awg()
        {
            m_destroyed = true;
            haltIo();
            goxtun_awg_free(m_handle);
            m_handle = nullptr;
        }

        ResultXtun<std::unique_ptr<Awg>> Awg::create(const std::string &str, ClientCallbacks callbacks)
        {
            auto res = awg::Config::fromConf(str);
            if (!res)
                return fail(res.error());

            auto awg = std::unique_ptr<Awg>(new Awg(callbacks, std::move(res).value()));
            Proxy *proxy = awg.get();

            void *handle = goxtun_awg_new(Proxy::cTunRead, Proxy::cTunWrite, Proxy::cTunMtu, proxy, Proxy::cEmitLog,
                                          Proxy::cEmitLog, proxy, Proxy::cSockCb, proxy);
            if (handle == nullptr) {
                return fail(LIBXTUN_ERR_SYSTEM);
            }
            awg->m_handle = handle;

            auto uapi = awg->m_conf.toUapi();
            if (char *err = goxtun_awg_setconf(handle, &uapi[0]); err != nullptr) {
                awg->emitLog(err);
                goxtun_free(err);
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }

            return awg;
        }

        void Awg::attachIo(TunnelIo *io)
        {
            if (io == nullptr) {
                Proxy::attachIo(io);
                return;
            }

            in_addr v4origin{}, v4target{};
            in6_addr v6origin{}, v6target{};

            for (const auto &prefix : io->addresses()) {
                const auto &addr = prefix.address();
                const auto bytes = addr.octets();

                switch (addr.family()) {
                case AF_INET: std::memcpy(&v4origin, bytes.data(), sizeof(v4origin)); break;
                case AF_INET6: std::memcpy(&v6origin, bytes.data(), sizeof(v6origin)); break;
                }
            }

            for (const auto &prefix : m_conf.iface().address) {
                const auto &addr = prefix.addr;

                switch (addr.family) {
                case AF_INET: v4target = addr.ip4; break;
                case AF_INET6: v6target = addr.ip6; break;
                }
            }

            auto remapio = std::make_unique<RemappingIo>(*io, v4origin, v4target, v6origin, v6target);
            Proxy::attachIo(remapio.get());
            m_remapio = std::move(remapio);
        }

        void Awg::event(ProxyEvent ev)
        {
            if (m_handle == nullptr) {
                return;
            }

            switch (ev) {
            case ProxyEvent::Up: goxtun_awg_event(m_handle, TunEventUp); break;
            case ProxyEvent::Down: goxtun_awg_event(m_handle, TunEventDown); break;
            case ProxyEvent::MtuUpdate: goxtun_awg_event(m_handle, TunEventMtuUpdate); break;
            }
        }

        ProxyProfile Awg::profile() const
        {
            const awg::Config::Interface &iface = m_conf.iface();

            ProxyProfile out;
            for (const auto &peer : iface.peers) {
                for (const auto &ip : peer.allowedIps) {
                    if (auto prefix = net::IpPrefix::parse(ip.toUapi())) {
                        out.routes.emplace_back(std::move(*prefix));
                    }
                }
            }
            for (const auto &server : iface.dns) {
                if (auto addr = net::IpAddress::parse(server.toUapi())) {
                    out.dnsServers.emplace_back(std::move(*addr));
                }
            }
            return out;
        }
    }
}
