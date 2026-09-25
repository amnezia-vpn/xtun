#include "awaiting_io.h"
#include "tunnel_io.h"
#include <mutex>
#include <utility>

namespace libxtun
{
    AwaitingIo::AwaitingIo(TunnelIo *io) : m_io(io)
    {
    }

    AwaitingIo::AwaitingIo()
    {
    }

    AwaitingIo::~AwaitingIo()
    {
        destroy();
    }

    int AwaitingIo::read(std::span<std::byte> buf)
    {
        return withIo([&buf](TunnelIo &io) { return io.read(buf); });
    }

    int AwaitingIo::write(std::span<const std::byte> packet)
    {
        return withIo([&packet](TunnelIo &io) { return io.write(packet); });
    }

    int AwaitingIo::mtu() const
    {
        std::unique_lock lock(m_mutex);
        if (m_io) {
            return m_io->mtu();
        }
        return 0;
    }

    std::vector<net::IpPrefix> AwaitingIo::addresses()
    {
        std::unique_lock lock(m_mutex);
        if (m_io) {
            return m_io->addresses();
        }
        return {};
    }

    void AwaitingIo::protectSocket(int fd)
    {
        std::unique_lock lock(m_mutex);
        if (m_io) {
            m_io->protectSocket(fd);
        }
    }

    void AwaitingIo::halt()
    {
        std::unique_lock lock(m_mutex);
        if (m_io) {
            m_io->halt();
        }
        m_haltEpoch++;
        m_cv.notify_all();
    }

    void AwaitingIo::assign(TunnelIo *io)
    {
        std::unique_lock lock(m_mutex);
        assignLocked(lock, io);
    }

    void AwaitingIo::assignLocked(std::unique_lock<std::mutex> &lock, TunnelIo *io)
    {
        if (m_io == io) {
            return;
        }

        if (TunnelIo *io = std::exchange(m_io, nullptr)) {
            io->halt();
            m_usersCv.wait(lock, [this]() { return m_users == 0; });
        }

        m_io = io;
        m_cv.notify_all();
    }

    void AwaitingIo::destroy()
    {
        std::unique_lock lock(m_mutex);
        m_destroyed = true;
        m_cv.notify_all();
        assignLocked(lock, nullptr);
    }

    template<typename F> auto AwaitingIo::withIo(F &&f) -> std::invoke_result_t<F, TunnelIo &>
    {
        using R = std::invoke_result_t<F, TunnelIo &>;

        std::unique_lock lock(m_mutex);
        int haltEpoch = m_haltEpoch;
        m_cv.wait(lock, [&]() { return m_io || m_haltEpoch != haltEpoch || m_destroyed; });
        if (m_destroyed) {
            return R { -1 };
        }
        if (m_haltEpoch != haltEpoch) {
            return R { 0 };
        }
        m_users++;

        TunnelIo* io = m_io;
        lock.unlock();
        R res = f(*io);
        lock.lock();

        if (--m_users == 0) {
            m_usersCv.notify_all();
        }
        return res;
    }
}
