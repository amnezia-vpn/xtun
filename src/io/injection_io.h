#ifndef INJECTION_IO
#define INJECTION_IO

#include "tunnel_io.h"
#include <condition_variable>
#include <mutex>

namespace libxtun
{
    class InjectionIo : public TunnelIo
    {
    public:
        InjectionIo(TunnelIo &io);
        ~InjectionIo();

        void inject(std::span<const std::byte> pkt);

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;
        void protectSocket(int fd) override;
        void wake() override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

    private:
        TunnelIo &m_io;
        std::mutex m_mutex;
        std::condition_variable m_cond;
        std::span<const std::byte> *m_pending = nullptr;
        bool m_awake = false;
        bool m_halted = false;
    };
}

#endif // INJECTION_IO
