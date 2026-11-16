#ifndef TEST_MEMPROXY_H
#define TEST_MEMPROXY_H

#include "proxy.h"
#include <condition_variable>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>

namespace libxtun::test
{
    class MemProxy final : public Proxy
    {
    public:
        MemProxy(libxtun::ClientCallbacks callbacks, ProxyProfile profile = {},
                 std::vector<net::IpPrefix> includeRoutes = {}, std::vector<net::IpPrefix> excludeRoutes = {})
            : Proxy(callbacks), m_profile(std::move(profile))
        {
            m_includeRoutes = std::move(includeRoutes);
            m_excludeRoutes = std::move(excludeRoutes);
        }

        ~MemProxy()
        {
            stop();
        };

        const char *name() override
        {
            return "memproxy";
        }

        void setEventListener(std::function<void(ProxyEvent)> listener)
        {
            m_eventListener = std::move(listener);
        }

        void event(ProxyEvent ev) override
        {
            if (m_eventListener) {
                m_eventListener(ev);
            }
            switch (ev) {
            case ProxyEvent::Up: start(); break;
            case ProxyEvent::Down: stop(); break;
            default: break;
            }
        }

        void injectPacket(std::span<const std::byte> packet)
        {
            std::scoped_lock lock(m_sendMutex);
            m_sendBuf.assign(packet.begin(), packet.end());
            m_sendCv.notify_all();
        }

        int waitForArrival(std::span<std::byte> buf, std::chrono::milliseconds timeout)
        {
            std::unique_lock lock(m_rcvMutex);
            m_rcvCv.wait_for(lock, timeout, [this]() { return m_rcvBuf.empty() || m_stopped; });

            size_t n = std::min(buf.size(), m_rcvBuf.size());
            std::memcpy(buf.data(), m_rcvBuf.data(), n);
            m_rcvBuf.clear();
            return n;
        }

    protected:
        ProxyProfile buildProfile() const override
        {
            return m_profile;
        }

        void start()
        {
            std::scoped_lock lock(m_threadMutex);
            if (!m_stopped) {
                return;
            }
            m_stopped = false;
            m_rcvThread = std::thread(&MemProxy::receiveWorker, this);
            m_sendThread = std::thread(&MemProxy::sendWorker, this);
        }
        void stop()
        {
            std::scoped_lock lock(m_threadMutex);

            m_stopped = true;
            m_io.halt();
            m_rcvCv.notify_all();
            m_sendCv.notify_all();

            if (m_rcvThread.joinable()) {
                m_rcvThread.join();
            }
            if (m_sendThread.joinable()) {
                m_sendThread.join();
            }
        }

        void sendWorker()
        {
            while (!m_stopped) {
                std::unique_lock lock(m_sendMutex);
                m_sendCv.wait(lock, [this]() { return !m_sendBuf.empty() || m_stopped; });

                if (!m_sendBuf.empty()) {
                    int _ = tunWrite(m_sendBuf.data(), m_sendBuf.size());
                    m_sendBuf.clear();
                }
            }
        }
        void receiveWorker()
        {
            std::array<std::byte, 2048> buf;

            while (!m_stopped) {
                int n = tunRead(buf.data(), buf.size());
                if (n > 0) {
                    std::scoped_lock lock(m_rcvMutex);
                    m_rcvBuf.assign(buf.begin(), buf.begin() + n);
                    m_rcvCv.notify_all();
                }
            }
        }

    private:
        ProxyProfile m_profile;
        std::function<void(ProxyEvent)> m_eventListener;
        std::atomic<bool> m_stopped = true;
        std::mutex m_rcvMutex, m_sendMutex, m_threadMutex;
        std::vector<std::byte> m_rcvBuf, m_sendBuf;
        std::condition_variable m_rcvCv, m_sendCv;
        std::thread m_rcvThread, m_sendThread;
    };
}

#endif
