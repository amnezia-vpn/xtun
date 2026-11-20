#ifndef DISPATCH_DISPATCHER_H
#define DISPATCH_DISPATCHER_H

#include "dispatch/classifier.h"
#include "io/injection_io.h"
#include "proxy.h"
#include "tunnel_io.h"
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace libxtun::dispatch
{
    class Dispatcher
    {
    public:
        Dispatcher(TunnelIo &io);
        ~Dispatcher();

        bool attach(Proxy *proxy);
        bool detach(Proxy *proxy);
        void clear();
        bool empty() const;

        void event(ProxyEvent ev);
        ProxyProfile profile() const;

    private:
        struct Entry
        {
            std::unique_ptr<InjectionIo> io;
            std::uint64_t priority;
        };
        using IoMap = std::map<Proxy *, Entry>;

        InjectionIo *pickIo(std::span<const std::byte> pkt) const;
        void teardown(Proxy *proxy, IoMap::mapped_type &entry);
        void pump() const;
        void upLocked();
        void downLocked();

        std::thread m_pump;
        std::atomic_bool m_stop = false;
        mutable std::mutex m_mutex;
        mutable std::mutex m_tableMutex;

        TunnelIo &m_io;
        IoMap m_iomap;
        std::vector<std::unique_ptr<Classifier>> m_classifiers;
        std::uint64_t m_nextPriority = 0;
    };
}

#endif // DISPATCH_DISPATCHER_H
