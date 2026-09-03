#ifndef LIBXTUN_TUN_DEVICE_H
#define LIBXTUN_TUN_DEVICE_H

#include "tunnel_io.h"

#include <cstddef>
#include <memory>
#include <span>
#include <string>

namespace libxtun
{
    class TunDeviceListener
    {
    public:
        virtual ~TunDeviceListener() = default;

        virtual void onLinkStateChanged(bool up) = 0;
        virtual void onMtuChanged(int mtu) = 0;
        virtual void onRouteChanged() = 0;
    };

    class TunDevice : public TunnelIo
    {
    public:
        virtual ~TunDevice() = default;

        virtual int open() = 0;
        virtual int adoptFd(int fd) = 0;
        virtual int adoptName(const char *name) = 0;

        int read(std::span<std::byte> buf) noexcept override = 0;
        int write(std::span<const std::byte> buf) noexcept override = 0;
        int mtu() const noexcept override = 0;

        virtual const std::string &name() const noexcept = 0;
        virtual int ifIndex() const noexcept = 0;
        virtual bool up() const noexcept = 0;

        virtual void resetReadCancellation() noexcept = 0;
        virtual void wakeRead() noexcept = 0;
        virtual void cancelRead() noexcept = 0;

        virtual void startMonitor(TunDeviceListener &listener) = 0;
        virtual void stopMonitor() noexcept = 0;
    };

    std::unique_ptr<TunDevice> createTunDevice();

}

#endif // LIBXTUN_TUN_DEVICE_H
