#include "awg.h"
#include "awg_conf.h"
#include "proxy.h"
#include "xtun.h"

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
                    out.routes.push_back(ip.toUapi());
                }
            }
            for (const auto &server : iface.dns) {
                out.dnsServers.push_back(server.toUapi());
            }
            if (iface.address.has_value()) {
                out.addresses.push_back(iface.address->toUapi());
            }
            return out;
        }
    }
}
