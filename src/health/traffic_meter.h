#ifndef HEALTH_TRAFFIC_METER_H
#define HEALTH_TRAFFIC_METER_H

#include <atomic>
#include <cstdint>

namespace libxtun::health
{

    class TrafficMeter
    {
    public:
        struct Counters
        {
            uint64_t outboundPackets = 0;
            uint64_t inboundPackets = 0;
            uint64_t outboundBytes = 0;
            uint64_t inboundBytes = 0;
        };

        TrafficMeter() noexcept = default;

        void recordOutbound(int bytes) noexcept
        {
            m_outboundPackets.fetch_add(1, std::memory_order_relaxed);
            m_outboundBytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
        }

        void recordInbound(int bytes) noexcept
        {
            m_inboundPackets.fetch_add(1, std::memory_order_relaxed);
            m_inboundBytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
        }

        Counters counters() const noexcept
        {
            return { m_outboundPackets.load(std::memory_order_relaxed),
                     m_inboundPackets.load(std::memory_order_relaxed),
                     m_outboundBytes.load(std::memory_order_relaxed), m_inboundBytes.load(std::memory_order_relaxed) };
        }

        uint64_t inboundPackets() const noexcept
        {
            return m_inboundPackets.load(std::memory_order_relaxed);
        }

    private:
        std::atomic<uint64_t> m_outboundPackets { 0 };
        std::atomic<uint64_t> m_inboundPackets { 0 };
        std::atomic<uint64_t> m_outboundBytes { 0 };
        std::atomic<uint64_t> m_inboundBytes { 0 };
    };

}

#endif // HEALTH_TRAFFIC_METER_H
