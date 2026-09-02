#include "control_probe.h"

#include "net/socket.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>

namespace libxtun::health {

namespace {

constexpr std::chrono::milliseconds kAbortPollSlice{250};

}

ControlProbe::ControlProbe(BindSocket bind, std::optional<net::SockAddr> peer)
    : m_bind(std::move(bind)), m_peer(std::move(peer)) {}

ProbeOutcome ControlProbe::run(const DnsQuery &query, std::chrono::milliseconds timeout) {
    if (!m_bind || !m_peer) {
        return ProbeOutcome::NotRun;
    }
    const int family = m_peer->data()->sa_family;
    auto socket = net::Socket::udp(family);
    if (!socket) {
        return ProbeOutcome::NotRun;
    }

    m_aborted.store(false, std::memory_order_release);
    m_bind(socket->native(), family);

    if (!socket->connect(*m_peer) || !socket->send(query.bytes())) {
        return ProbeOutcome::Failed;
    }

    std::array<std::byte, kMaxDnsResponse> buf{};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!m_aborted.load(std::memory_order_acquire)) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining <= std::chrono::milliseconds::zero()) {
            return ProbeOutcome::Failed;
        }
        if (!socket->waitReadable(std::min(remaining, kAbortPollSlice))) {
            continue;
        }
        const auto received = socket->receive(buf);
        if (!received) {
            return ProbeOutcome::Failed;
        }
        if (query.matchesResponse({buf.data(), *received})) {
            return ProbeOutcome::Answered;
        }
    }
    return ProbeOutcome::NotRun;
}

void ControlProbe::abort() noexcept {
    m_aborted.store(true, std::memory_order_release);
}

}
