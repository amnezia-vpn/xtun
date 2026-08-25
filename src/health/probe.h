#ifndef HEALTH_PROBE_H
#define HEALTH_PROBE_H

#include <chrono>
#include <cstddef>
#include <span>

namespace libxtun::health {

class DnsQuery;

enum class ProbeOutcome { NotRun, Answered, Failed };

class ConnectivityProbe {
  public:
    virtual ~ConnectivityProbe() = default;

    [[nodiscard]] virtual ProbeOutcome run(const DnsQuery &query,
                                           std::chrono::milliseconds timeout) = 0;
    virtual void abort() noexcept = 0;
};

class PacketInterceptor {
  public:
    virtual ~PacketInterceptor() = default;

    virtual int stage(std::span<std::byte> buf) noexcept = 0;
    [[nodiscard]] virtual bool capture(std::span<const std::byte> packet) noexcept = 0;
};

class TunnelProbe : public ConnectivityProbe, public PacketInterceptor {};

}

#endif // HEALTH_PROBE_H
