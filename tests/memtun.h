#ifndef MEMTUN_H
#define MEMTUN_H

#include "tunnel_io.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <deque>
#include <mutex>
#include <span>
#include <vector>

class MemTun final : public libxtun::TunnelIo
{
public:
    int read(std::span<std::byte> buf) noexcept override
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock, [this] { return m_cancelled || !m_in.empty(); });
        if (m_cancelled) {
            return libxtun::IO_FATAL;
        }
        std::vector<unsigned char> pkt = std::move(m_in.front());
        m_in.pop_front();
        size_t n = pkt.size() > buf.size() ? buf.size() : pkt.size();
        std::memcpy(buf.data(), pkt.data(), n);
        return static_cast<int>(n);
    }

    int write(std::span<const std::byte> packet) noexcept override
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto *p = reinterpret_cast<const unsigned char *>(packet.data());
        m_out.emplace_back(p, p + packet.size());
        m_cond.notify_all();
        return static_cast<int>(packet.size());
    }

    int mtu() const noexcept override
    {
        return 1420;
    }

    void inject(const std::vector<unsigned char> &pkt)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_in.push_back(pkt);
        m_cond.notify_all();
    }

    bool awaitDelivery(std::vector<unsigned char> &pkt, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (!m_cond.wait_for(lock, timeout, [this] { return !m_out.empty(); })) {
            return false;
        }
        pkt = std::move(m_out.front());
        m_out.pop_front();
        return true;
    }

    void cancel()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cancelled = true;
        m_cond.notify_all();
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cond;
    std::deque<std::vector<unsigned char>> m_in;
    std::deque<std::vector<unsigned char>> m_out;
    bool m_cancelled = false;
};

#endif // MEMTUN_H
