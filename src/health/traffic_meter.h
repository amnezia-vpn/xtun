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
            uint64_t outbound_packets = 0;
            uint64_t inbound_packets = 0;
            uint64_t outbound_bytes = 0;
            uint64_t inbound_bytes = 0;
        };

        TrafficMeter() noexcept = default;

        void recordOutbound(int bytes) noexcept
        {
            m_outbound_packets.fetch_add(1, std::memory_order_relaxed);
            m_outbound_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
        }

        void recordInbound(int bytes) noexcept
        {
            m_inbound_packets.fetch_add(1, std::memory_order_relaxed);
            m_inbound_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
        }

        Counters counters() const noexcept
        {
            return { m_outbound_packets.load(std::memory_order_relaxed),
                     m_inbound_packets.load(std::memory_order_relaxed),
                     m_outbound_bytes.load(std::memory_order_relaxed), m_inbound_bytes.load(std::memory_order_relaxed) };
        }

        uint64_t inboundPackets() const noexcept
        {
            return m_inbound_packets.load(std::memory_order_relaxed);
        }

    private:
        std::atomic<uint64_t> m_outbound_packets { 0 };
        std::atomic<uint64_t> m_inbound_packets { 0 };
        std::atomic<uint64_t> m_outbound_bytes { 0 };
        std::atomic<uint64_t> m_inbound_bytes { 0 };
    };

}

#endif // HEALTH_TRAFFIC_METER_H
