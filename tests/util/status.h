#ifndef TEST_STATUS_H
#define TEST_STATUS_H

#include "proxy.h"
#include "xtun.h"
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace libxtun::test
{
    class StatusChecker
    {
    public:
        ClientCallbacks &wrapCallbacks(ClientCallbacks &callbacks)
        {
            callbacks.onStatus = StatusChecker::cOnStatus;
            callbacks.onStatusPriv = this;
            return callbacks;
        }

        libxtun_proxy &wrapProxy(libxtun_proxy &proxy)
        {
            proxy.statushandler = StatusChecker::cOnStatus;
            proxy.statushandler_priv = this;
            return proxy;
        }

        static void cOnStatus(int status, void *priv)
        {
            reinterpret_cast<StatusChecker *>(priv)->onStatus(status);
        }

        void onStatus(int status)
        {
            std::unique_lock lock(m_mutex);
            m_status = status;
            m_cv.notify_all();
        }

        bool await(int status, std::chrono::milliseconds time = std::chrono::seconds(1))
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, time, [&]() { return m_status == status; });
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        int m_status = LIBXTUN_STATUS_DISCONNECTED;
    };

}
#endif
