#ifndef AWAITING_IO_H
#define AWAITING_IO_H

#include "tunnel_io.h"
#include <condition_variable>
#include <mutex>

namespace libxtun
{
    class AwaitingIo : public TunnelIo
    {
    public:
        explicit AwaitingIo(TunnelIo *io);
        AwaitingIo();
        ~AwaitingIo();

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;
        void protectSocket(int fd) override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

        void assign(TunnelIo *io);

    private:
        void haltLocked(std::unique_lock<std::mutex> &lock);

        class IoOperation
        {
        public:
            IoOperation(const AwaitingIo &self, std::unique_lock<std::mutex> &lock, bool waitForNonNull = true);
            ~IoOperation();

            TunnelIo *io()
            {
                return m_io;
            }

        private:
            const AwaitingIo &m_self;
            TunnelIo *m_io = nullptr;
            std::unique_lock<std::mutex> &m_lock;
        };

        TunnelIo *m_io = nullptr;

        mutable bool m_halted = false;
        mutable int m_users = 0;
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
    };
}

#endif
