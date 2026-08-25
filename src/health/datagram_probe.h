#ifndef HEALTH_DATAGRAM_PROBE_H
#define HEALTH_DATAGRAM_PROBE_H

#include "health/dns_query.h"
#include "health/probe.h"
#include "health/resolver_pool.h"
#include "net/ip.h"
#include "util/noncopyable.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <span>
#include <vector>

namespace libxtun::health {

class DatagramProbe final : public TunnelProbe, private NonCopyable {
  public:
    using WakeReader = std::function<void()>;

    DatagramProbe(const ResolverPool &resolvers, WakeReader wake);

    ProbeOutcome run(const DnsQuery &query, std::chrono::milliseconds timeout) override;
    void abort() noexcept override;

    int stage(std::span<std::byte> buf) noexcept override;
    bool capture(std::span<const std::byte> packet) noexcept override;

  private:
    const ResolverPool &m_resolvers;
    WakeReader m_wake;

    mutable std::mutex m_mtx;
    std::condition_variable m_cond;
    DnsQuery m_query;
    std::vector<std::byte> m_datagram;
    net::IpAddress m_source;
    net::IpAddress m_target;
    bool m_staged = false;
    bool m_answered = false;
    bool m_aborted = false;
    std::atomic<bool> m_awaiting{false};
};

}

#endif // HEALTH_DATAGRAM_PROBE_H
