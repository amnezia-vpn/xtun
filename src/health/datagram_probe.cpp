#include "datagram_probe.h"

#include "net/udp.h"

#include <cstring>
#include <utility>

namespace libxtun::health
{

    DatagramProbe::DatagramProbe(const ResolverPool &resolvers, WakeReader wake)
        : m_resolvers(resolvers), m_wake(std::move(wake))
    {
    }

    ProbeOutcome DatagramProbe::run(const DnsQuery &query, std::chrono::milliseconds timeout)
    {
        const auto target = m_resolvers.select(Reachability::InsideTunnel);
        if (!target) {
            return ProbeOutcome::NotRun;
        }
        const auto source = m_resolvers.localAddressFor(target->family());
        if (!source) {
            return ProbeOutcome::NotRun;
        }

        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_datagram = net::buildUdpDatagram(*source, *target, query.sourcePort(), DNS_PORT, query.bytes());
            if (m_datagram.empty()) {
                return ProbeOutcome::NotRun;
            }
            m_query = query;
            m_source = *source;
            m_target = *target;
            m_staged = false;
            m_answered = false;
            m_aborted = false;
            m_awaiting.store(true, std::memory_order_release);
        }

        if (m_wake) {
            m_wake();
        }

        std::unique_lock<std::mutex> lock(m_mtx);
        m_cond.wait_for(lock, timeout, [this] { return m_answered || m_aborted; });
        m_awaiting.store(false, std::memory_order_release);
        m_datagram.clear();

        if (m_answered) {
            return ProbeOutcome::Answered;
        }
        return m_aborted ? ProbeOutcome::NotRun : ProbeOutcome::Failed;
    }

    void DatagramProbe::abort() noexcept
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_aborted = true;
        m_awaiting.store(false, std::memory_order_release);
        m_cond.notify_all();
    }

    int DatagramProbe::stage(std::span<std::byte> buf) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (!m_awaiting.load(std::memory_order_relaxed) || m_staged || m_datagram.empty()
            || m_datagram.size() > buf.size()) {
            return 0;
        }
        std::memcpy(buf.data(), m_datagram.data(), m_datagram.size());
        m_staged = true;
        return static_cast<int>(m_datagram.size());
    }

    bool DatagramProbe::capture(std::span<const std::byte> packet) noexcept
    {
        if (!m_awaiting.load(std::memory_order_acquire)) {
            return false;
        }
        const auto udp = net::UdpDatagramView::parse(packet);
        if (!udp || udp->sourcePort() != DNS_PORT) {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_mtx);
        if (!m_awaiting.load(std::memory_order_relaxed) || udp->destinationPort() != m_query.sourcePort()
            || udp->source() != m_target || udp->destination() != m_source) {
            return false;
        }

        m_answered = m_query.matchesResponse(udp->payload());
        if (!m_answered) {
            return false;
        }
        m_awaiting.store(false, std::memory_order_release);
        m_cond.notify_all();
        return true;
    }

}
