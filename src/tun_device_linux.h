#ifndef LIBXTUN_TUN_DEVICE_LINUX_H
#define LIBXTUN_TUN_DEVICE_LINUX_H

#include "tun_device.h"

#include <atomic>
#include <thread>

namespace libxtun
{
    class LinuxTunDevice final : public TunDevice
    {
    public:
        int open() override;
        int adoptFd(int fd) override;
        int adoptName(const char *name) override;

        int read(std::span<std::byte> buf) noexcept override;
        int write(std::span<const std::byte> buf) noexcept override;
        int mtu() const noexcept override;

        const std::string &name() const noexcept override;
        int ifIndex() const noexcept override;
        bool up() const noexcept override;

        void resetReadCancellation() noexcept override;
        void wakeRead() noexcept override;
        void cancelRead() noexcept override;
        void startMonitor(TunDeviceListener &listener) override;
        void stopMonitor() noexcept override;

        ~LinuxTunDevice() override;

    private:
        int finishOpen();
        void closeTun() noexcept;
        void monitorLoop() noexcept;

        int m_tunFd = -1;
        std::string m_name;
        int m_ifIndex = -1;
        int m_readCancelFd = -1;

        int m_monitorFd = -1;
        int m_monitorCancelFd = -1;
        std::thread m_monitor;
        std::atomic<bool> m_readCancelled { false };
        std::atomic<bool> m_injectPending { false };
        std::atomic<bool> m_up { false };
        std::atomic<int> m_mtu { 0 };
        TunDeviceListener *m_listener = nullptr;
    };
}

#endif // LIBXTUN_TUN_DEVICE_LINUX_H
