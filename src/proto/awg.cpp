#include "awg.h"
#include "awg_conf.h"
#include "health/dns_probe.h"
#include "health/health_io.h"
#include "health/icmp_probe.h"
#include "health/probe.h"
#include "io/remapping_io.h"
#include "net/ip.h"
#include "proxy.h"
#include "tunnel_io.h"
#include "xtun.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <libgoxtun.h>

#include <memory>
#include <ranges>

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

namespace libxtun::proto
{
    namespace
    {
        net::IpAddress toIpAddress(const awg::IpAddrField &f) noexcept
        {
            switch (f.family) {
            case AF_INET: return net::IpAddress::fromV4(f.ip4);
            case AF_INET6: return net::IpAddress::fromV6(f.ip6);
            default: return {};
            }
        }

        net::IpPrefix toIpPrefix(const awg::PrefixField &f) noexcept
        {
            return { toIpAddress(f.addr), f.cidr };
        }
    }

    Awg::Awg(ClientCallbacks callbacks, awg::Config conf) : Proxy(callbacks), m_conf(std::move(conf))
    {
        const auto &v = m_conf.iface().address;
        m_ifaceAddress.reserve(v.size());
        std::ranges::transform(v, std::back_inserter(m_ifaceAddress),
                               [](const awg::PrefixField &p) { return toIpPrefix(p); });
    }

    Awg::~Awg()
    {
        if (m_healthio) {
            m_healthio->stop();
        }
        m_io.halt();
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
            m_remapio.reset();
            m_healthio.reset();
            m_probe.reset();
            return;
        }

        const auto prof = profile();

        auto probe = [&]() -> std::unique_ptr<health::Probe> {
            if (m_callbacks.onStatus == nullptr) {
                return std::make_unique<health::DummyProbe>();
            }

            auto included = [&](const net::IpAddress &addr) {
                return std::ranges::any_of(prof.routes,
                                           [&](const net::IpPrefix &prefix) { return prefix.contains(addr); });
            };
            // take AllowedIPs-included DNS to probe, if any
            for (const auto &addr : prof.dnsServers | std::views::filter(included)) {
                if (auto probeio = health::DnsProbe::create(*io, addr)) {
                    io = probeio.get();
                    return probeio;
                }
            }
            // make the server to probe the proxy back (or to send Time Exceeded due to TTL) using its own address
            for (const auto &prefix : m_ifaceAddress) {
                if (auto probeio = health::IcmpProbe::create(*io, prefix.address())) {
                    io = probeio.get();
                    return probeio;
                }
            }
            // fallback to Dummy
            return std::make_unique<health::DummyProbe>();
        }();

        auto healthio = std::make_unique<health::HealthIo>(*io, *probe, *this, health::HealthIoOptions());
        io = healthio.get();

        auto remapio = RemappingIo::create(*io, m_ifaceAddress);
        if (remapio) {
            io = remapio.get();
        }

        Proxy::attachIo(io);

        m_remapio = std::move(remapio);
        if (auto prev = std::exchange(m_healthio, std::move(healthio))) {
            prev->stop();
        }
        m_healthio->start();
        m_probe = std::move(probe);
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
        case ProxyEvent::UplinkUpdate:
            goxtun_awg_event(m_handle, TunEventDown);
            goxtun_awg_event(m_handle, TunEventUp);
            break;
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
        if (auto mtu = iface.mtu) {
            out.mtu = mtu->val;
        }
        return out;
    }
}
