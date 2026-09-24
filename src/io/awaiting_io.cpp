#include "awaiting_io.h"
#include <mutex>

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
        std::unique_lock lock(m_mutex);
        IoOperation op(*this, lock);
        if (auto *io = op.io()) {
            return io->read(buf);
        }
        return -1;
    }

    int AwaitingIo::write(std::span<const std::byte> packet)
    {
        std::unique_lock lock(m_mutex);
        IoOperation op(*this, lock);
        if (auto *io = op.io()) {
            return io->write(packet);
        }
        return -1;
    }

    int AwaitingIo::mtu() const
    {
        std::unique_lock lock(m_mutex);
        IoOperation op(*this, lock, false);
        if (auto *io = op.io()) {
            return io->mtu();
        }
        return 0;
    }

    std::vector<net::IpPrefix> AwaitingIo::addresses()
    {
        std::unique_lock lock(m_mutex);
        IoOperation op(*this, lock, false);
        if (auto *io = op.io()) {
            return io->addresses();
        }
        return {};
    }

    void AwaitingIo::protectSocket(int fd)
    {
        std::unique_lock lock(m_mutex);
        IoOperation op(*this, lock);
        if (auto *io = op.io()) {
            io->protectSocket(fd);
        }
    }

    void AwaitingIo::assign(TunnelIo *io)
    {
        std::unique_lock lock(m_mutex);
        haltLocked(lock);
        m_halted = false;
        m_io = io;
        m_cv.notify_all();
    }

    void AwaitingIo::halt()
    {
        std::unique_lock lock(m_mutex);
        haltLocked(lock);
    }

    void AwaitingIo::haltLocked(std::unique_lock<std::mutex> &lock)
    {
        {
            IoOperation op(*this, lock, false);
            if (auto *io = op.io()) {
                io->halt();
            }
        }
        m_halted = true;
        m_cv.notify_all();
        m_cv.wait(lock, [this]() { return m_users == 0; });
    }

    AwaitingIo::IoOperation::IoOperation(const AwaitingIo &self, std::unique_lock<std::mutex> &lock, bool waitForNonNull)
        : m_self(self), m_lock(lock)
    {
        ++self.m_users;
        if (waitForNonNull) {
            self.m_cv.wait(lock, [&self]() { return self.m_io != nullptr || self.m_halted; });
        }
        m_io = self.m_halted ? nullptr : self.m_io;
        m_lock.unlock();
    }

    AwaitingIo::IoOperation::~IoOperation()
    {
        m_lock.lock();
        --m_self.m_users;
        if (m_self.m_halted) {
            m_self.m_cv.notify_all();
        }
    }
}
