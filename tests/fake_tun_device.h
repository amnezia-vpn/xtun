#ifndef LIBXTUN_TESTS_FAKE_TUN_DEVICE_H
#define LIBXTUN_TESTS_FAKE_TUN_DEVICE_H

#include "tun_device.h"
#include "xtun.h"

#include <span>
#include <string>

class FakeTunDevice final : public libxtun::TunDevice
{
public:
    explicit FakeTunDevice(int mtu = 0) : m_mtu(mtu)
    {
    }

    int open() override
    {
        return LIBXTUN_OK;
    }
    int adoptFd(int fd) override
    {
        (void)fd;
        return LIBXTUN_OK;
    }
    int adoptName(const char *name) override
    {
        m_name = name;
        return LIBXTUN_OK;
    }

    int read(std::span<std::byte> buf) noexcept override
    {
        (void)buf;
        return -1;
    }
    int write(std::span<const std::byte> buf) noexcept override
    {
        (void)buf;
        return -1;
    }
    int mtu() const noexcept override
    {
        return m_mtu;
    }

    const std::string &name() const noexcept override
    {
        return m_name;
    }

    int ifIndex() const noexcept override
    {
        return -1;
    }

    bool up() const noexcept override
    {
        return false;
    }

    void resetReadCancellation() noexcept override
    {
    }
    void wakeRead() noexcept override
    {
    }
    void cancelRead() noexcept override
    {
    }
    void startMonitor(libxtun::TunDeviceListener &listener) override
    {
        (void)listener;
    }
    void stopMonitor() noexcept override
    {
    }

private:
    std::string m_name;
    int m_mtu;
};

#endif // LIBXTUN_TESTS_FAKE_TUN_DEVICE_H
