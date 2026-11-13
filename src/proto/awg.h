#ifndef AWG_H
#define AWG_H

#include "../proxy.h"

#include "awg_conf.h"
#include "health/health_io.h"
#include "health/probe.h"
#include "io/remapping_io.h"
#include "net/ip.h"
#include "util/result.h"

#include <memory>
#include <string>

namespace libxtun
{
    namespace proto
    {
        class Awg final : public Proxy, public health::HealthListener
        {
        public:
            static ResultXtun<std::unique_ptr<Awg>> create(const std::string &str, ClientCallbacks callbacks);
            ~Awg() override;

            void event(ProxyEvent ev) override;
            void attachIo(TunnelIo *io) override;

            const char *name() override
            {
                return "awg";
            }

            void onStatusChange(libxtun_status status) override
            {
                publishStatus(status);
            }

        protected:
            ProxyProfile buildProfile() const override;

        private:
            Awg(ClientCallbacks callbacks, awg::Config conf);

            awg::Config m_conf;
            void *m_handle = nullptr;

            std::vector<net::IpPrefix> m_ifaceAddress;

            std::unique_ptr<health::Probe> m_probe;
            std::unique_ptr<health::HealthIo> m_healthio;
            std::unique_ptr<RemappingIo> m_remapio;
        };
    }
}

#endif // AWG_H
