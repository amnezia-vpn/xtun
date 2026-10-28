#ifndef LIBXTUN_DNS_LINUX_H
#define LIBXTUN_DNS_LINUX_H

#include "dns.h"
#include "xtun.h"

#include <systemd/sd-bus.h>

#include <memory>
#include <utility>

namespace libxtun
{
    struct SdBusDeleter
    {
        void operator()(sd_bus *bus) const noexcept
        {
            sd_bus_unref(bus);
        }
    };

    struct SdBusMessageDeleter
    {
        void operator()(sd_bus_message *message) const noexcept
        {
            sd_bus_message_unref(message);
        }
    };

    struct SdBusErrorDeleter
    {
        void operator()(sd_bus_error *error) const noexcept
        {
            sd_bus_error_free(error);
        }
    };

    class LinuxDns final : public Dns
    {
    public:
        LinuxDns(std::unique_ptr<sd_bus, SdBusDeleter> bus, int ifIndex) noexcept
            : m_bus(std::move(bus)), m_ifIndex(ifIndex)
        {
        }

        static std::unique_ptr<LinuxDns> open(int ifIndex);

        libxtun_error apply(const std::vector<net::IpAddress> &resolvers) override;
        void revert() noexcept override;

    private:
        std::unique_ptr<sd_bus, SdBusDeleter> m_bus;
        int m_ifIndex = -1;
    };
}

#endif // LIBXTUN_DNS_LINUX_H
