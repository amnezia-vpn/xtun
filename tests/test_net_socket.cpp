#include "net/ip.h"
#include "net/socket.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <utility>

#if !defined(_WIN32)
    #include <fcntl.h>
#endif

namespace
{

    using libxtun::net::IpAddress;
    using libxtun::net::SockAddr;
    using libxtun::net::Socket;

    bool descriptorIsOpen(int fd)
    {
#if defined(_WIN32)
        WSAPROTOCOL_INFOW info {};
        int len = sizeof(info);
        return ::getsockopt(libxtun::net::fromAbiDescriptor(fd), SOL_SOCKET, SO_PROTOCOL_INFOW,
                            reinterpret_cast<char *>(&info), &len)
                == 0;
#else
        return ::fcntl(fd, F_GETFD) != -1;
#endif
    }

} // namespace

TEST(NetSocket, UdpOpensBothFamilies)
{
    auto v4 = Socket::udp(AF_INET);
    ASSERT_TRUE(v4.has_value());
    EXPECT_TRUE(descriptorIsOpen(v4->native()));

    auto v6 = Socket::udp(AF_INET6);
    if (v6.has_value()) {
        EXPECT_TRUE(descriptorIsOpen(v6->native()));
        EXPECT_NE(v6->native(), v4->native());
    }
}

TEST(NetSocket, ClosesExactlyOnceWhenScopeEnds)
{
    int fd = -1;
    {
        auto socket = Socket::udp(AF_INET);
        ASSERT_TRUE(socket.has_value());
        fd = socket->native();
        ASSERT_TRUE(descriptorIsOpen(fd));
    }

    EXPECT_FALSE(descriptorIsOpen(fd)) << "the descriptor outlived its owner";
}

TEST(NetSocket, MovedFromSocketDoesNotCloseTheDescriptor)
{
    auto source = Socket::udp(AF_INET);
    ASSERT_TRUE(source.has_value());
    const int fd = source->native();

    {
        Socket moved(std::move(*source));
        EXPECT_EQ(moved.native(), fd);
        EXPECT_TRUE(descriptorIsOpen(fd));
    }
    EXPECT_FALSE(descriptorIsOpen(fd));

    auto reuser = Socket::udp(AF_INET);
    ASSERT_TRUE(reuser.has_value());
    source.reset();

    EXPECT_TRUE(descriptorIsOpen(reuser->native()))
            << "destroying the moved-from socket closed whatever took over its descriptor";
}

TEST(NetSocket, MoveAssignmentClosesTheOverwrittenDescriptor)
{
    auto first = Socket::udp(AF_INET);
    auto second = Socket::udp(AF_INET);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    const int overwritten = first->native();
    const int kept = second->native();
    ASSERT_NE(overwritten, kept);

    *first = std::move(*second);

    EXPECT_FALSE(descriptorIsOpen(overwritten));
    EXPECT_EQ(first->native(), kept);
    EXPECT_TRUE(descriptorIsOpen(kept));
}

TEST(NetSocket, ConnectAndSendReachALocalListener)
{
    auto listener = Socket::udp(AF_INET);
    ASSERT_TRUE(listener.has_value());

    sockaddr_in bound {};
    bound.sin_family = AF_INET;
    bound.sin_port = 0;
    ::inet_pton(AF_INET, "127.0.0.1", &bound.sin_addr);
    ASSERT_EQ(::bind(libxtun::net::fromAbiDescriptor(listener->native()), reinterpret_cast<sockaddr *>(&bound),
                     sizeof(bound)),
              0);

    sockaddr_in assigned {};
    socklen_t assignedLen = sizeof(assigned);
    ASSERT_EQ(::getsockname(libxtun::net::fromAbiDescriptor(listener->native()),
                            reinterpret_cast<sockaddr *>(&assigned), &assignedLen),
              0);

    auto sender = Socket::udp(AF_INET);
    ASSERT_TRUE(sender.has_value());
    const SockAddr peer(IpAddress::parse("127.0.0.1").value(), ntohs(assigned.sin_port));
    ASSERT_TRUE(sender->connect(peer));

    const std::array<std::byte, 4> payload { std::byte { 'p' }, std::byte { 'i' }, std::byte { 'n' }, std::byte { 'g' } };
    ASSERT_TRUE(sender->send(payload));

    ASSERT_TRUE(listener->waitReadable(std::chrono::milliseconds(500)));
    std::array<std::byte, 16> buf {};
    const auto received = listener->receive(buf);
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(*received, payload.size());
    EXPECT_EQ(buf[0], std::byte { 'p' });
}

TEST(NetSocket, WaitReadableTimesOutOnASilentSocket)
{
    auto socket = Socket::udp(AF_INET);
    ASSERT_TRUE(socket.has_value());

    const auto started = std::chrono::steady_clock::now();
    EXPECT_FALSE(socket->waitReadable(std::chrono::milliseconds(20)));
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(1));
}
