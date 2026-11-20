#include "injection_io.h"
#include "net/ip.h"
#include "tunnel_io.h"
#include <algorithm>
#include <mutex>

namespace libxtun
{
    InjectionIo::InjectionIo(TunnelIo &io) : m_io(io)
    {
    }

    InjectionIo::~InjectionIo()
    {
    }

    void InjectionIo::inject(std::span<const std::byte> pkt)
    {
        std::unique_lock lock(m_mutex);
        m_pending = &pkt;
        m_cond.notify_all();
        m_cond.wait(lock, [&]() { return !m_pending || m_halted; });
        m_pending = nullptr;
    }

    int InjectionIo::read(std::span<std::byte> buf)
    {
        std::unique_lock lock(m_mutex);

        bool fits = false;
        std::size_t n;
        do {
            m_cond.wait(lock, [&]() { return m_pending || m_awake || m_halted; });
            if (m_awake) {
                m_awake = false;
                return READ_WAKE;
            }
            if (m_halted) {
                return IO_FATAL;
            }
            n = m_pending->size();
            fits = n <= buf.size();
            if (fits) {
                std::ranges::copy(*m_pending, buf.data());
            }
            m_pending = nullptr;
            m_cond.notify_all();
        } while (!fits);
        return static_cast<int>(n);
    }

    int InjectionIo::write(std::span<const std::byte> packet)
    {
        return m_io.write(packet);
    }

    void InjectionIo::protectSocket(int fd)
    {
        m_io.protectSocket(fd);
    }

    void InjectionIo::halt()
    {
        std::unique_lock lock(m_mutex);
        m_cond.notify_all();
        m_halted = true;
    }

    void InjectionIo::wake()
    {
        std::unique_lock lock(m_mutex);
        m_cond.notify_all();
        m_awake = true;
    }

    int InjectionIo::mtu() const
    {
        return m_io.mtu();
    }

    std::vector<net::IpPrefix> InjectionIo::addresses()
    {
        return m_io.addresses();
    }
}
