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
        halt();
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

    libxtun_error AwaitingIo::protectSocket(int fd)
    {
        std::unique_lock lock(m_mutex);
        if (!m_halted && m_io) {
            return m_io->protectSocket(fd);
        }
        return LIBXTUN_ERR_UNSUPPORTED;
    }

    void AwaitingIo::wake()
    {
        std::unique_lock lock(m_mutex);
        if (m_io) {
            m_io->wake();
        }
        m_wakeEpoch++;
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
            io->wake();
            m_usersCv.wait(lock, [this]() { return m_users == 0; });
        }

        m_io = io;
        m_cv.notify_all();
    }

    void AwaitingIo::halt()
    {
        std::unique_lock lock(m_mutex);
        m_halted = true;
        m_cv.notify_all();
        assignLocked(lock, nullptr);
    }

    template<typename F> auto AwaitingIo::withIo(F &&f) -> std::invoke_result_t<F, TunnelIo &>
    {
        using R = std::invoke_result_t<F, TunnelIo &>;

        std::unique_lock lock(m_mutex);
        int wakeEpoch = m_wakeEpoch;
        m_cv.wait(lock, [&]() { return m_io || m_wakeEpoch != wakeEpoch || m_halted; });
        if (m_halted) {
            return R { IO_FATAL };
        }
        if (m_wakeEpoch != wakeEpoch) {
            return R { READ_WAKE };
        }
        m_users++;

        TunnelIo *io = m_io;
        lock.unlock();
        R res = f(*io);
        lock.lock();

        if (--m_users == 0) {
            m_usersCv.notify_all();
        }
        if (m_halted) {
            return R { IO_FATAL };
        }
        if (m_io != io || m_wakeEpoch != wakeEpoch) {
            return R { READ_WAKE };
        }
        return res;
    }
}
