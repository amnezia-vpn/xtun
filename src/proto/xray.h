#ifndef XRAY_H
#define XRAY_H

#include "../proxy.h"
#include "health/health_monitor.h"
#include "health/probe.h"
#include "tunnel_io.h"
#include "util/result.h"
#include "xtun.h"
#include <memory>
#include <string>

namespace libxtun::proto
{
    class Xray : public Proxy, public health::HealthListener
    {
    public:
        static ResultXtun<std::unique_ptr<Xray>> create(const std::string &str, ClientCallbacks callbacks);
        ~Xray();

        ProxyProfile buildProfile() const override;
        void event(ProxyEvent ev) override;
        void attachIo(TunnelIo *io) override;
        void onStatusChange(libxtun_status status) override;

        const char *name() override
        {
            return "xray";
        }

    private:
        Xray(ClientCallbacks callbacks);
        void *m_handle = nullptr;
        std::unique_ptr<health::Probe> m_probe;
        std::unique_ptr<health::HealthMonitor> m_health;
    };

}

#endif // XRAY_H
