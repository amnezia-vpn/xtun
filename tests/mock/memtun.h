#ifndef TEST_MEMTUN_H
#define TEST_MEMTUN_H

#include "net/ip.h"
#include "responder.h"
#include "tunnel_io.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <deque>
#include <mutex>
#include <span>
#include <vector>

namespace libxtun::test
{
    class MemTun final : public libxtun::TunnelIo
    {
    public:
        ~MemTun()
        {
            wake();
        }

        int read(std::span<std::byte> buf) override
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            int wakeEpoch = m_wakeEpoch;
            m_cond.wait(lock, [&] { return !m_in.empty() || m_wakeEpoch != wakeEpoch || m_halted; });
            if (m_halted) {
                return -1;
            }
            if (wakeEpoch != m_wakeEpoch) {
                return 0;
            }
            const auto &pkt = m_in.front();
            size_t n = pkt.size() > buf.size() ? buf.size() : pkt.size();
            std::memcpy(buf.data(), pkt.data(), n);
            m_in.pop_front();
            return static_cast<int>(n);
        }

        int write(std::span<const std::byte> packet) override
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            if (auto reply = Responder::replyIcmp(packet); !reply.empty()) {
                m_in.push_back(reply);
                m_cond.notify_all();
            }

            if (auto reply = Responder::replyTcpSyn(packet); !reply.empty()) {
                m_in.push_back(reply);
                m_cond.notify_all();
            }

            if (auto reply = Responder::replyDns(packet); !reply.empty()) {
                m_in.push_back(reply);
                m_cond.notify_all();
            }

            m_out.emplace_back(packet.data(), packet.data() + packet.size());
            m_cond.notify_all();
            return static_cast<int>(packet.size());
        }

        int mtu() const override
        {
            return 1420;
        }

        void protectSocket(int fd) override
        {
            (void)fd;
        }

        void wake() override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_wakeEpoch++;
            m_cond.notify_all();
        }

        void halt() override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_halted = true;
            m_cond.notify_all();
        }

        std::vector<net::IpPrefix> addresses() override
        {
            auto def = net::IpPrefix::parse("10.9.9.1/32");
            return { *def };
        }

        void injectPacket(std::span<const std::byte> packet)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_in.push_back({ packet.begin(), packet.end() });
            m_cond.notify_all();
        }

        int waitForArrival(std::span<std::byte> buf, std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            int wakeEpoch = m_wakeEpoch;
            if (!m_cond.wait_for(lock, timeout, [&] { return !m_out.empty() || m_wakeEpoch != wakeEpoch || m_halted; })
                || m_out.empty()) {
                return 0;
            }
            auto &vec = m_out.front();
            size_t n = std::min(buf.size(), vec.size());
            std::memcpy(buf.data(), vec.data(), n);
            m_out.pop_front();
            return n;
        }

    private:
        mutable std::mutex m_mutex;
        mutable int m_wakeEpoch = 0;
        mutable bool m_halted = false;
        std::condition_variable m_cond;
        std::deque<std::vector<std::byte>> m_in;
        std::deque<std::vector<std::byte>> m_out;
    };
}

#endif // MEMTUN_H
