#ifndef AWAITING_IO_H
#define AWAITING_IO_H

#include "tunnel_io.h"
#include <condition_variable>
#include <mutex>
#include <type_traits>

namespace libxtun
{
    class AwaitingIo final : public TunnelIo
    {
    public:
        explicit AwaitingIo(TunnelIo *io);
        AwaitingIo();
        ~AwaitingIo();

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;
        void protectSocket(int fd) override;
        void wake() override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

        void assign(TunnelIo *io);

    private:
        void assignLocked(std::unique_lock<std::mutex> &lock, TunnelIo *io);
        template<typename F> auto withIo(F &&f) -> std::invoke_result_t<F, TunnelIo &>;

        TunnelIo *m_io = nullptr;

        mutable bool m_halted = false;
        mutable int m_wakeEpoch = 0;
        mutable int m_users = 0;
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
        mutable std::condition_variable m_usersCv;
    };
}

#endif
