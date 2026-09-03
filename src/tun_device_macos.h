#ifndef LIBXTUN_TUN_DEVICE_MACOS_H
#define LIBXTUN_TUN_DEVICE_MACOS_H

#include "tun_device.h"

#include <atomic>
#include <thread>

namespace libxtun
{
    class MacosTunDevice final : public TunDevice
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

        ~MacosTunDevice() override;

    private:
        int finishOpen();
        void closeTun() noexcept;
        void monitorLoop() noexcept;

        int m_tunFd = -1;
        std::string m_name;
        int m_ifIndex = -1;
        int m_readCancelRd = -1;
        int m_readCancelWr = -1;

        int m_monitorFd = -1;
        std::thread m_monitor;
        std::atomic<bool> m_read_cancelled { false };
        std::atomic<bool> m_inject_pending { false };
        std::atomic<bool> m_up { false };
        std::atomic<int> m_mtu { 0 };
        TunDeviceListener *m_listener = nullptr;
    };
}

#endif // LIBXTUN_TUN_DEVICE_MACOS_H
