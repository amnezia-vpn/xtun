#include "dns_linux.h"
#include "net/ip.h"
#include "xtun.h"

#include <systemd/sd-bus.h>

#include <cstddef>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace libxtun
{
    namespace
    {
        constexpr const char *RESOLVED_NAME = "org.freedesktop.resolve1";
        constexpr const char *RESOLVED_PATH = "/org/freedesktop/resolve1";
        constexpr const char *RESOLVED_MANAGER = "org.freedesktop.resolve1.Manager";

        class BusMessage final : private NonCopyable
        {
        public:
            BusMessage(sd_bus *bus, const char *member) : m_bus(bus)
            {
                sd_bus_message *raw = nullptr;
                m_status = sd_bus_message_new_method_call(bus, &raw, RESOLVED_NAME, RESOLVED_PATH, RESOLVED_MANAGER,
                                                          member);
                m_message.reset(raw);
            }

            template<typename... A> BusMessage &append(const char *types, A... args)
            {
                return then([&](sd_bus_message *message) { return sd_bus_message_append(message, types, args...); });
            }

            BusMessage &open(char type, const char *contents)
            {
                return then([&](sd_bus_message *message) {
                    return sd_bus_message_open_container(message, type, contents);
                });
            }

            BusMessage &close()
            {
                return then(sd_bus_message_close_container);
            }

            BusMessage &appendBytes(std::span<const std::byte> bytes)
            {
                return then([&](sd_bus_message *message) {
                    return sd_bus_message_append_array(message, 'y', bytes.data(), bytes.size());
                });
            }

            int send()
            {
                if (m_status < 0) {
                    return m_status;
                }

                sd_bus_error error = SD_BUS_ERROR_NULL;
                const std::unique_ptr<sd_bus_error, SdBusErrorDeleter> errorGuard(&error);
                return sd_bus_call(m_bus, m_message.get(), 0, &error, nullptr);
            }

        private:
            template<typename F> BusMessage &then(F &&call)
            {
                if (m_status >= 0) {
                    m_status = call(m_message.get());
                }
                return *this;
            }

            sd_bus *m_bus;
            std::unique_ptr<sd_bus_message, SdBusMessageDeleter> m_message;
            int m_status = 0;
        };

        int setLinkDns(sd_bus *bus, int ifIndex, const std::vector<net::IpAddress> &resolvers)
        {
            BusMessage message(bus, "SetLinkDNS");
            message.append("i", ifIndex).open('a', "(iay)");
            for (const net::IpAddress &resolver : resolvers) {
                message.open('r', "iay").append("i", resolver.family()).appendBytes(resolver.octets()).close();
            }
            return message.close().send();
        }

        int setLinkDomains(sd_bus *bus, int ifIndex)
        {
            return BusMessage(bus, "SetLinkDomains")
                    .append("i", ifIndex)
                    .open('a', "(sb)")
                    .append("(sb)", ".", 1)
                    .close()
                    .send();
        }
    }

    std::unique_ptr<LinuxDns> LinuxDns::open(int ifIndex)
    {
        sd_bus *rawBus = nullptr;
        if (sd_bus_open_system(&rawBus) < 0) {
            return nullptr;
        }
        std::unique_ptr<sd_bus, SdBusDeleter> bus(rawBus);

        sd_bus_error error = SD_BUS_ERROR_NULL;
        const std::unique_ptr<sd_bus_error, SdBusErrorDeleter> errorGuard(&error);
        sd_bus_message *rawReply = nullptr;
        const int rc = sd_bus_call_method(bus.get(), "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                          "org.freedesktop.DBus", "NameHasOwner", &error, &rawReply, "s",
                                          RESOLVED_NAME);
        const std::unique_ptr<sd_bus_message, SdBusMessageDeleter> reply(rawReply);

        int hasOwner = 0;
        if (rc < 0 || sd_bus_message_read(reply.get(), "b", &hasOwner) < 0 || hasOwner == 0) {
            return nullptr;
        }
        return std::make_unique<LinuxDns>(std::move(bus), ifIndex);
    }

    libxtun_error LinuxDns::apply(const std::vector<net::IpAddress> &resolvers)
    {
        if (resolvers.empty()) {
            revert();
            return LIBXTUN_OK;
        }

        if (setLinkDns(m_bus.get(), m_ifIndex, resolvers) < 0 || setLinkDomains(m_bus.get(), m_ifIndex) < 0) {
            revert();
            return LIBXTUN_ERR_DNS;
        }
        return LIBXTUN_OK;
    }

    void LinuxDns::revert() noexcept
    {
        BusMessage(m_bus.get(), "RevertLink").append("i", m_ifIndex).send();
    }
}
