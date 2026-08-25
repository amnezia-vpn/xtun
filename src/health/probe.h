#ifndef HEALTH_PROBE_H
#define HEALTH_PROBE_H

#include <cstddef>
#include <span>

namespace libxtun::health {

class PacketInterceptor {
  public:
    virtual ~PacketInterceptor() = default;

    virtual int stage(std::span<std::byte> buf) noexcept = 0;
    [[nodiscard]] virtual bool capture(std::span<const std::byte> packet) noexcept = 0;
};

}

#endif // HEALTH_PROBE_H
