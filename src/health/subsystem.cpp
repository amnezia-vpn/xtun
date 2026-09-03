#include "subsystem.h"

#include "health/datagram_probe.h"

#include <memory>
#include <utility>

namespace libxtun::health
{
    namespace
    {

        std::unique_ptr<TunnelProbe> makeTunnelProbe(ProbeStyle style, const ResolverPool &resolvers,
                                                     DatagramProbe::WakeReader wake)
        {
            std::unique_ptr<TunnelProbe> probe;
            switch (style) {
            case ProbeStyle::Datagram: probe = std::make_unique<DatagramProbe>(resolvers, std::move(wake)); break;
            }
            return probe;
        }

    }

    HealthSubsystem::HealthSubsystem(HealthListener &listener, HealthConfig config, const Clock &clock)
        : m_queries(m_random),
          m_resolvers(config.dnsServers, config.tunnelAddresses, config.tunnelRoutes),
          m_tunnelProbe(makeTunnelProbe(config.probeStyle, m_resolvers, std::move(config.wakeRead))),
          m_controlProbe(std::move(config.bindSocket), m_resolvers),
          m_scheduler(m_random, config.settings.jitterPercent, config.log),
          m_monitor(config.settings, listener, m_meter, *m_tunnelProbe, m_controlProbe, m_queries, m_scheduler, clock,
                    std::move(config.log))
    {
    }

    HealthSubsystem::~HealthSubsystem()
    {
        stop();
    }

    TunnelIo &HealthSubsystem::decorate(TunnelIo &device)
    {
        m_io.emplace(device, m_meter, *m_tunnelProbe);
        return *m_io;
    }

    void HealthSubsystem::start()
    {
        m_monitor.start();
    }

    void HealthSubsystem::stop() noexcept
    {
        m_tunnelProbe->abort();
        m_controlProbe.abort();
        m_monitor.stop();
    }

    void HealthSubsystem::halt() noexcept
    {
        if (m_io.has_value()) {
            m_io->halt();
        }
    }

    void HealthSubsystem::onNetworkChanged() noexcept
    {
        m_monitor.requestReset();
        m_scheduler.wake();
    }

}
