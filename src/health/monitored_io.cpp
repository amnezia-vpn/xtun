#include "monitored_io.h"

namespace libxtun::health {

MonitoredIo::MonitoredIo(TunnelIo &device, TrafficMeter &meter,
                         PacketInterceptor &interceptor) noexcept
    : m_device(device), m_meter(meter), m_interceptor(interceptor) {}

int MonitoredIo::read(std::span<std::byte> buf) noexcept {
    for (;;) {
        if (halted()) {
            return kIoFatal;
        }
        const int n = m_device.read(buf);
        if (n != kReadWake) {
            if (n > 0) {
                m_meter.recordOutbound(n);
            }
            return n;
        }
        if (const int staged = m_interceptor.stage(buf); staged > 0) {
            return staged;
        }
    }
}

int MonitoredIo::write(std::span<const std::byte> packet) noexcept {
    if (halted()) {
        return kIoFatal;
    }
    if (m_interceptor.capture(packet)) {
        return static_cast<int>(packet.size());
    }
    const int n = m_device.write(packet);
    if (n > 0) {
        m_meter.recordInbound(n);
    }
    return n;
}

}
