#ifndef HEALTH_SUBSYSTEM_H
#define HEALTH_SUBSYSTEM_H

#include "health/control_probe.h"
#include "health/dns_query.h"
#include "health/monitor.h"
#include "health/monitored_io.h"
#include "health/probe.h"
#include "health/resolver_pool.h"
#include "health/scheduler.h"
#include "health/state.h"
#include "health/traffic_meter.h"
#include "tunnel_io.h"
#include "util/clock.h"
#include "util/noncopyable.h"
#include "util/random.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::health
{

    struct HealthConfig
    {
        std::vector<std::string> dns_servers;
        std::vector<std::string> tunnel_addresses;
        std::vector<std::string> tunnel_routes;
        ProbeStyle probe_style = ProbeStyle::Datagram;
        HealthSettings settings;
        ControlProbe::BindSocket bind_socket;
        std::function<void()> wake_read;
        LogSink log;
    };

    class HealthSubsystem final : private NonCopyable
    {
    public:
        HealthSubsystem(HealthListener &listener, HealthConfig config, const Clock &clock = RealClock::instance());
        ~HealthSubsystem();

        [[nodiscard]] TunnelIo &decorate(TunnelIo &device);

        void start();
        void stop() noexcept;
        void halt() noexcept;
        void onNetworkChanged() noexcept;

    private:
        RandomSource m_random;
        DnsQueryFactory m_queries;
        ResolverPool m_resolvers;
        TrafficMeter m_meter;
        std::unique_ptr<TunnelProbe> m_tunnel_probe;
        ControlProbe m_control_probe;
        ThreadedScheduler m_scheduler;
        HealthMonitor m_monitor;
        std::optional<MonitoredIo> m_io;
    };

}

#endif // HEALTH_SUBSYSTEM_H
