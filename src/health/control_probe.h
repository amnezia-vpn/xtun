#ifndef HEALTH_CONTROL_PROBE_H
#define HEALTH_CONTROL_PROBE_H

#include "health/dns_query.h"
#include "health/probe.h"
#include "net/ip.h"
#include "util/noncopyable.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <optional>

namespace libxtun::health {

class ControlProbe final : public ConnectivityProbe, private NonCopyable {
  public:
    using BindSocket = std::function<void(int fd, int family)>;

    ControlProbe(BindSocket bind, std::optional<net::SockAddr> peer);

    ProbeOutcome run(const DnsQuery &query, std::chrono::milliseconds timeout) override;
    void abort() noexcept override;

  private:
    BindSocket m_bind;
    std::optional<net::SockAddr> m_peer;
    std::atomic<bool> m_aborted{false};
};

}

#endif // HEALTH_CONTROL_PROBE_H
