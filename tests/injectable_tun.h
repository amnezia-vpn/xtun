#ifndef INJECTABLE_TUN_H
#define INJECTABLE_TUN_H

#include "tunnel_io.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <deque>
#include <mutex>
#include <span>
#include <vector>

class InjectableTun final : public libxtun::TunnelIo {
  public:
    static constexpr auto kPollSlice = std::chrono::milliseconds(20);

    int read(std::span<std::byte> buf) noexcept override {
        std::unique_lock<std::mutex> lock(m_mtx);
        m_cond.wait_for(lock, kPollSlice,
                        [this] { return m_cancelled || m_wakes > 0 || !m_in.empty(); });
        if (m_cancelled) {
            return libxtun::kIoFatal;
        }
        if (!m_in.empty()) {
            const std::vector<std::byte> packet = std::move(m_in.front());
            m_in.pop_front();
            const std::size_t n = std::min(packet.size(), buf.size());
            std::memcpy(buf.data(), packet.data(), n);
            return static_cast<int>(n);
        }
        if (m_wakes > 0) {
            --m_wakes;
        }
        return libxtun::kReadWake;
    }

    int write(std::span<const std::byte> packet) noexcept override {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_out.emplace_back(packet.begin(), packet.end());
        ++m_written;
        m_cond.notify_all();
        return static_cast<int>(packet.size());
    }

    int mtu() const noexcept override { return 1420; }

    void wake() {
        std::lock_guard<std::mutex> lock(m_mtx);
        ++m_wakes;
        m_cond.notify_all();
    }

    void inject(std::vector<std::byte> packet) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_in.push_back(std::move(packet));
        m_cond.notify_all();
    }

    bool awaitWrite(std::vector<std::byte> &packet, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(m_mtx);
        if (!m_cond.wait_for(lock, timeout, [this] { return !m_out.empty(); })) {
            return false;
        }
        packet = std::move(m_out.front());
        m_out.pop_front();
        return true;
    }

    std::size_t written() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_written;
    }

    void cancel() {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_cancelled = true;
        m_cond.notify_all();
    }

  private:
    mutable std::mutex m_mtx;
    std::condition_variable m_cond;
    std::deque<std::vector<std::byte>> m_in;
    std::deque<std::vector<std::byte>> m_out;
    std::size_t m_written = 0;
    int m_wakes = 0;
    bool m_cancelled = false;
};

#endif // INJECTABLE_TUN_H
