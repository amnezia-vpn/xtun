#include "xray.h"
#include "health/dns_probe.h"
#include "health/health_monitor.h"
#include "health/probe.h"
#include "net/ip.h"
#include "proxy.h"
#include "tunnel_io.h"
#include "util/result.h"
#include "xtun.h"
#include <cassert>
#include <libgoxtun.h>
#include <memory>
#include <string>
#include <utility>

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
    Xray::Xray(ClientCallbacks callbacks) : Proxy(callbacks)
    {
    }

    Xray::~Xray()
    {
        if (m_health) {
            m_health->stop();
        }
        m_io.halt();
        goxtun_xray_free(m_handle);
        m_handle = nullptr;
    }

    ResultXtun<std::unique_ptr<Xray>> Xray::create(const std::string &str, ClientCallbacks callbacks)
    {
        auto xray = std::unique_ptr<Xray>(new Xray(std::move(callbacks)));
        Proxy *proxy = xray.get();

        xray->m_handle = goxtun_xray_new(Proxy::cTunRead, Proxy::cTunWrite, Proxy::cTunMtu, proxy, Proxy::cEmitLog,
                                         Proxy::cEmitLog, proxy, Proxy::cSockCb, proxy, const_cast<char *>(str.c_str()));
        if (!xray->m_handle) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        return xray;
    }

    ProxyProfile Xray::buildProfile() const
    {
        return ProxyProfile { {
                net::IpPrefix(net::IpAddress::fromV4(in_addr {}), 0),
                net::IpPrefix(net::IpAddress::fromV6(in6_addr {}), 0),
        } };
    }

    void Xray::event(ProxyEvent ev)
    {
        switch (ev) {
        case ProxyEvent::Up: goxtun_xray_event(m_handle, TunEventUp); break;
        case ProxyEvent::Down: goxtun_xray_event(m_handle, TunEventDown); break;
        case ProxyEvent::MtuUpdate: goxtun_xray_event(m_handle, TunEventMtuUpdate); break;
        }
    }

    void Xray::onStatusChange(libxtun_status status)
    {
        publishStatus(status);
    }

    void Xray::attachIo(TunnelIo *io)
    {
        if (io == nullptr) {
            Proxy::attachIo(io);
            m_health.reset();
            m_probe.reset();
            return;
        }

        auto probe = [&]() -> std::unique_ptr<health::Probe> {
            if (m_callbacks.onStatus == nullptr) {
                return std::make_unique<health::DummyProbe>();
            }

            const static auto defaultDnsAddr = net::IpAddress::parse("8.8.8.8");
            if (auto probe = health::DnsProbe::create(*io, defaultDnsAddr.value())) {
                io = probe.get();
                return probe;
            }

            return std::make_unique<health::DummyProbe>();
        }();

        auto health = std::make_unique<health::HealthMonitor>([this]() { return goxtun_xray_downlink_bytes(m_handle); },
                                                              *probe, *this, health::HealthIoOptions());

        Proxy::attachIo(io);

        if (auto prev = std::exchange(m_health, std::move(health))) {
            prev->stop();
        }
        m_health->start();
        m_probe = std::move(probe);
    }
}
