#ifndef LIBXTUN_NET_NETLINK_H
#define LIBXTUN_NET_NETLINK_H

#include "xtun.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <type_traits>
#include <unistd.h>

namespace libxtun::net::netlink
{
    class NetlinkRequest final
    {
    public:
        NetlinkRequest(int type, int extraFlags, std::size_t payloadSize) noexcept
        {
            header().nlmsg_len = static_cast<std::uint32_t>(NLMSG_LENGTH(payloadSize));
            header().nlmsg_type = static_cast<std::uint16_t>(type);
            header().nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_ACK | extraFlags);
        }

        struct nlmsghdr &header() noexcept
        {
            return *reinterpret_cast<struct nlmsghdr *>(m_buf.data());
        }

        template<typename T> T &payload() noexcept
        {
            return *reinterpret_cast<T *>(NLMSG_DATA(&header()));
        }

        template<typename T> requires std::is_trivially_copyable_v<T>
        void attribute(int type, const T &value) noexcept
        {
            const std::size_t offset = NLMSG_ALIGN(header().nlmsg_len);
            if (offset + RTA_SPACE(sizeof(T)) > m_buf.size()) {
                m_truncated = true;
                return;
            }

            auto *attr = reinterpret_cast<struct rtattr *>(m_buf.data() + offset);
            attr->rta_type = static_cast<unsigned short>(type);
            attr->rta_len = static_cast<unsigned short>(RTA_LENGTH(sizeof(T)));
            std::memcpy(RTA_DATA(attr), &value, sizeof(T));
            header().nlmsg_len = static_cast<std::uint32_t>(offset + RTA_ALIGN(attr->rta_len));
        }

        [[nodiscard]] int send() noexcept
        {
            const int sock = openSock();
            if (sock < 0) {
                return sock;
            }

            std::array<std::byte, 4096> reply {};
            const ssize_t received = ::recv(sock, reply.data(), reply.size(), 0);
            ::close(sock);
            if (received < 0) {
                return -errno;
            }

            ssize_t left = received;
            for (auto *message = reinterpret_cast<struct nlmsghdr *>(reply.data()); NLMSG_OK(message, left);
                 message = NLMSG_NEXT(message, left)) {
                if (message->nlmsg_type == NLMSG_ERROR) {
                    return reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(message))->error;
                }
            }
            return 0;
        }

        template<typename F> [[nodiscard]] int dump(F &&visit) noexcept
        {
            const int sock = openSock();
            if (sock < 0) {
                return sock;
            }

            alignas(NLMSG_ALIGNTO) std::array<std::byte, 32768> reply {};
            while (true) {
                const ssize_t received = ::recv(sock, reply.data(), reply.size(), 0);
                if (received < 0) {
                    const int err = -errno;
                    ::close(sock);
                    return err;
                }

                ssize_t left = received;
                for (auto *message = reinterpret_cast<struct nlmsghdr *>(reply.data()); NLMSG_OK(message, left);
                     message = NLMSG_NEXT(message, left)) {
                    if (message->nlmsg_type == NLMSG_DONE) {
                        ::close(sock);
                        return 0;
                    }
                    if (message->nlmsg_type == NLMSG_ERROR) {
                        ::close(sock);
                        return reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(message))->error;
                    }
                    visit(*message);
                }
            }
        }

    private:
        [[nodiscard]] int openSock() noexcept
        {
            if (m_truncated) {
                return -EMSGSIZE;
            }

            const int sock = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (sock < 0) {
                return -errno;
            }

            struct sockaddr_nl destAddr;
            std::memset(&destAddr, 0, sizeof(destAddr));
            destAddr.nl_family = AF_NETLINK;

            if (::sendto(sock, m_buf.data(), header().nlmsg_len, 0,
                         reinterpret_cast<const struct sockaddr *>(&destAddr), sizeof(destAddr)) < 0) {
                const int err = -errno;
                ::close(sock);
                return err;
            }
            return sock;
        }

        alignas(NLMSG_ALIGNTO) std::array<std::byte, 512> m_buf {};
        bool m_truncated = false;
    };

    inline libxtun_error updateRule(bool add, int family, bool invert, uint32_t fwmark, uint32_t table,
                                              int suppressPrefixLen, uint32_t priority) noexcept
    {
        NetlinkRequest request(add ? RTM_NEWRULE : RTM_DELRULE,
                    add ? NLM_F_CREATE | NLM_F_EXCL : 0, sizeof(struct fib_rule_hdr));
        auto &rule = request.payload<struct fib_rule_hdr>();
        rule.family = static_cast<unsigned char>(family);
        rule.action = FR_ACT_TO_TBL;
        rule.table = RT_TABLE_UNSPEC;
        if (invert) {
            rule.flags |= FIB_RULE_INVERT;
        }

        if (suppressPrefixLen >= 0) {
            request.attribute<std::uint32_t>(FRA_SUPPRESS_PREFIXLEN, suppressPrefixLen);
        }
        if (fwmark != 0) {
            request.attribute<std::uint32_t>(FRA_FWMARK, fwmark);
        }
        request.attribute<std::uint32_t>(FRA_PRIORITY, priority);
        request.attribute<std::uint32_t>(FRA_TABLE, table);

        const int rc = request.send();
        return rc == 0 || (add && rc == -EEXIST) ? LIBXTUN_OK : LIBXTUN_ERR_KILLSWITCH;
    }

    template<typename HEADER> std::optional<std::uint32_t> u32Attribute(const struct nlmsghdr &message, int type) noexcept
    {
        int left = static_cast<int>(message.nlmsg_len) - static_cast<int>(NLMSG_LENGTH(sizeof(HEADER)));
        for (const auto *attr = reinterpret_cast<const struct rtattr *>(
                     reinterpret_cast<const std::byte *>(NLMSG_DATA(&message)) + NLMSG_ALIGN(sizeof(HEADER)));
             RTA_OK(attr, left); attr = RTA_NEXT(attr, left)) {
            if (attr->rta_type == type && static_cast<std::size_t>(RTA_PAYLOAD(attr)) >= sizeof(std::uint32_t)) {
                std::uint32_t value = 0;
                std::memcpy(&value, RTA_DATA(attr), sizeof(value));
                return value;
            }
        }
        return std::nullopt;
    }

    inline int ruleCount(int family, std::uint32_t priority) noexcept
    {
        NetlinkRequest request(RTM_GETRULE, NLM_F_DUMP, sizeof(struct fib_rule_hdr));
        request.payload<struct fib_rule_hdr>().family = static_cast<unsigned char>(family);

        int count = 0;
        const int rc = request.dump([&count, priority](const struct nlmsghdr &message) {
            if (message.nlmsg_type == RTM_NEWRULE
                && u32Attribute<struct fib_rule_hdr>(message, FRA_PRIORITY) == priority) {
                ++count;
            }
        });
        return rc < 0 ? rc : count;
    }

    inline int routeCount(int family, std::uint32_t table) noexcept
    {
        NetlinkRequest request(RTM_GETROUTE, NLM_F_DUMP, sizeof(struct rtmsg));
        request.payload<struct rtmsg>().rtm_family = static_cast<unsigned char>(family);

        int count = 0;
        const int rc = request.dump([&count, table](const struct nlmsghdr &message) {
            if (message.nlmsg_type == RTM_NEWROUTE && u32Attribute<struct rtmsg>(message, RTA_TABLE) == table) {
                ++count;
            }
        });
        return rc < 0 ? rc : count;
    }
}
#endif
