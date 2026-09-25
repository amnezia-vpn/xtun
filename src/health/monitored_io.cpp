#include "monitored_io.h"

namespace libxtun::health
{
    MonitoredIo::MonitoredIo(TunnelIo &device, TrafficMeter &meter, PacketInterceptor &interceptor) noexcept
        : m_device(device), m_meter(meter), m_interceptor(interceptor)
    {
    }

    int MonitoredIo::read(std::span<std::byte> buf) noexcept
    {
        int n = m_device.read(buf);
        if (n == 0) {
            if (int staged = m_interceptor.stage(buf); staged > 0) {
                return staged;
            }
        }
        if (n > 0) {
            m_meter.recordOutbound(n);
        }
        return n;
    }

    int MonitoredIo::write(std::span<const std::byte> packet) noexcept
    {
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
