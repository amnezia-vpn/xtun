#ifndef TUNNEL_IO_H
#define TUNNEL_IO_H

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <span>

namespace libxtun
{
    inline constexpr int READ_WAKE = 0;
    inline constexpr int IO_FATAL = -1;

    class TunnelIo
    {
    public:
        virtual ~TunnelIo() = default;

        virtual int read(std::span<std::byte> buf) = 0;
        virtual int write(std::span<const std::byte> packet) = 0;
        virtual int mtu() const = 0;
        virtual void protectSocket(int fd) = 0;
        virtual void halt() = 0;
    };

    class WrappedIo : public TunnelIo
    {
    public:
        explicit WrappedIo(TunnelIo *io) : m_io(io)
        {
        }

        WrappedIo()
        {
        }

        ~WrappedIo()
        {
            halt();
        }

        int read(std::span<std::byte> buf) override
        {
            IoOperation op(*this);
            if (auto *io = op.io()) {
                return io->read(buf);
            }
            return -1;
        }
        int write(std::span<const std::byte> packet) override
        {
            IoOperation op(*this);
            if (auto *io = op.io()) {
                return io->write(packet);
            }
            return -1;
        }
        int mtu() const override
        {
            IoOperation op(*this, false);
            if (auto *io = op.io()) {
                return io->mtu();
            }
            return 0;
        }
        void protectSocket(int fd) override
        {
            IoOperation op(*this);
            if (auto *io = op.io()) {
                io->protectSocket(fd);
            }
        }

        void assign(TunnelIo *io)
        {
            std::scoped_lock lock(m_mutex);
            m_io = io;
            m_cv.notify_all();
        }

        void halt() override
        {
            {
                IoOperation op(*this, false);
                if (auto *io = op.io()) {
                    io->halt();
                }
            }
            haltSelf();
        }

    protected:
        void haltSelf()
        {
            std::unique_lock lock(m_mutex);
            m_halted = true;
            m_cv.notify_all();
            m_cv.wait(lock, [this]() { return m_users == 0; });
        }

    private:
        class IoOperation
        {
        public:
            IoOperation(const WrappedIo &self, bool waitForNonNull = true) : m_self(self)
            {
                std::unique_lock lock(self.m_mutex);
                ++self.m_users;
                if (waitForNonNull) {
                    self.m_cv.wait(lock, [&self]() { return self.m_io != nullptr || self.m_halted; });
                }
                m_io = self.m_halted ? nullptr : self.m_io;
            }

            ~IoOperation()
            {
                std::scoped_lock lock(m_self.m_mutex);
                --m_self.m_users;
                if (m_self.m_halted) {
                    m_self.m_cv.notify_all();
                }
            }

            TunnelIo *io()
            {
                return m_io;
            }

        private:
            const WrappedIo &m_self;
            TunnelIo *m_io = nullptr;
        };

        TunnelIo *m_io = nullptr;

        mutable bool m_halted = false;
        mutable int m_users = 0;
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
    };
}

#endif // TUNNEL_IO_H
