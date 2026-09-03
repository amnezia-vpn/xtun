#include "awg.h"

#include <libgoxtun.h>

#include <cstdlib>
#include <memory>
#include <variant>

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

    int tunRead(void *b, int len, void *priv)
    {
        if (b == nullptr || len <= 0) {
            return libxtun::IO_FATAL;
        }
        auto *io = static_cast<libxtun::TunnelIo *>(priv);
        return io->read({ static_cast<std::byte *>(b), static_cast<std::size_t>(len) });
    }

    int tunWrite(void *b, int len, void *priv)
    {
        if (b == nullptr || len <= 0) {
            return libxtun::IO_FATAL;
        }
        auto *io = static_cast<libxtun::TunnelIo *>(priv);
        return io->write({ static_cast<const std::byte *>(b), static_cast<std::size_t>(len) });
    }

    int tunMtu(void *priv)
    {
        auto *io = static_cast<libxtun::TunnelIo *>(priv);
        return io->mtu();
    }

}

namespace libxtun
{
    namespace proto
    {

        Awg::Awg(awg::Config conf) : m_conf(std::move(conf))
        {
        }

        Awg::~Awg()
        {
            stop();
        }

        ResultXtun<std::unique_ptr<Awg>> Awg::create(const std::string &str)
        {
            auto res = awg::Config::fromConf(str);
            if (!res)
                return fail(res.error());
            return std::make_unique<Awg>(std::move(res).value());
        }

        int Awg::start(TunnelIo &io)
        {
            if (m_ctx != nullptr) {
                return LIBXTUN_ERR_INVALID_ARGS;
            }

            m_io = &io;

            m_ctx = goxtun_awg_new(tunRead, tunWrite, tunMtu, m_io, &Awg::forwardLog, &Awg::forwardLog, this,
                                   &Awg::sockCb, this);
            if (m_ctx == nullptr) {
                return LIBXTUN_ERR_SYSTEM;
            }

            auto uapi = m_conf.toUapi();
            if (char *err = goxtun_awg_setconf(m_ctx, &uapi[0]); err != nullptr) {
                emitLog(err);
                goxtun_free(err);
                return LIBXTUN_ERR_INVALID_ARGS;
            }

            return LIBXTUN_OK;
        }

        void Awg::event(ProxyEvent ev)
        {
            if (m_ctx == nullptr) {
                return;
            }

            switch (ev) {
            case ProxyEvent::Up: goxtun_awg_event(m_ctx, TunEventUp); break;
            case ProxyEvent::Down: goxtun_awg_event(m_ctx, TunEventDown); break;
            case ProxyEvent::MtuUpdate: goxtun_awg_event(m_ctx, TunEventMtuUpdate); break;
            }
        }

        void Awg::stop()
        {
            if (m_ctx == nullptr) {
                return;
            }

            cancelIo();
            goxtun_awg_free(m_ctx);
            m_ctx = nullptr;
        }

        void Awg::forwardLog(char *str, void *priv)
        {
            static_cast<Awg *>(priv)->emitLog(str);
        }

        void Awg::sockCb(int fd, void *priv)
        {
            auto *self = static_cast<Awg *>(priv);

            sockaddr_storage ss {};
#if defined(_WIN32)
            int len = sizeof(ss);
            if (::getsockname(static_cast<SOCKET>(fd), reinterpret_cast<sockaddr *>(&ss), &len) != 0) {
                return;
            }
#else
            socklen_t len = sizeof(ss);
            if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &len) != 0) {
                return;
            }
#endif

            self->registerBypassSocket(fd, ss.ss_family);
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
