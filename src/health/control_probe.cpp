#include "control_probe.h"

#include "net/socket.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>

namespace libxtun::health
{

    namespace
    {
        constexpr std::chrono::milliseconds ABORT_POLL_SLICE { 250 };
    }

    ControlProbe::ControlProbe(BindSocket bind, const ResolverPool &resolvers)
        : m_bind(std::move(bind)), m_resolvers(resolvers)
    {
    }

    ProbeOutcome ControlProbe::run(const DnsQuery &query, std::chrono::milliseconds timeout)
    {
        if (!m_bind) {
            return ProbeOutcome::NotRun;
        }
        const auto target = m_resolvers.select(Reachability::PhysicalInterface);
        if (!target) {
            return ProbeOutcome::NotRun;
        }
        auto socket = net::Socket::udp(target->family());
        if (!socket) {
            return ProbeOutcome::NotRun;
        }

        m_aborted.store(false, std::memory_order_release);
        m_bind(socket->native(), target->family());

        if (!socket->connect(net::SockAddr(*target, DNS_PORT)) || !socket->send(query.bytes())) {
            return ProbeOutcome::Failed;
        }

        std::array<std::byte, MAX_DNS_RESPONSE> buf {};
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!m_aborted.load(std::memory_order_acquire)) {
            const auto remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (remaining <= std::chrono::milliseconds::zero()) {
                return ProbeOutcome::Failed;
            }
            if (!socket->waitReadable(std::min(remaining, ABORT_POLL_SLICE))) {
                continue;
            }
            const auto received = socket->receive(buf);
            if (!received) {
                return ProbeOutcome::Failed;
            }
            if (query.matchesResponse({ buf.data(), *received })) {
                return ProbeOutcome::Answered;
            }
        }
        return ProbeOutcome::NotRun;
    }

    void ControlProbe::abort() noexcept
    {
        m_aborted.store(true, std::memory_order_release);
    }

}
