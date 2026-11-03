#include "io/awaiting_io.h"
#include "net/socket.h"
#include "proxy.h"
#include "router.h"

#include <gtest/gtest.h>

#if defined(_WIN32)
    #include <iphlpapi.h>
#endif

namespace
{
    class RecordingIo final : public libxtun::TunnelIo
    {
    public:
        libxtun_error result = LIBXTUN_OK;
        std::vector<int> protectedSockets;

        int read(std::span<std::byte>) override { return libxtun::IO_FATAL; }
        int write(std::span<const std::byte>) override { return libxtun::IO_FATAL; }
        void wake() override {}
        void halt() override {}
        int mtu() const override { return 1500; }
        std::vector<libxtun::net::IpPrefix> addresses() override { return {}; }

        libxtun_error protectSocket(int fd) override
        {
            protectedSockets.push_back(fd);
            return result;
        }
    };

    class TestProxy final : public libxtun::Proxy
    {
    public:
        explicit TestProxy(libxtun::ClientCallbacks callbacks = {}) : Proxy(callbacks) {}
        ~TestProxy() override { attachIo(nullptr); }

        using Proxy::cSockCb;
        using Proxy::sockCb;

        const char *name() override { return "test"; }
        void event(libxtun::ProxyEvent) override {}
        libxtun::ProxyProfile profile() const override { return {}; }
    };

#if defined(_WIN32)
    void checkUnboundSocketProtection(int family)
    {
        auto socket = libxtun::net::Socket::udp(family);
        ASSERT_TRUE(socket.has_value());

        PMIB_IPFORWARD_TABLE2 routes = nullptr;
        ASSERT_EQ(::GetIpForwardTable2(static_cast<ADDRESS_FAMILY>(family), &routes), NO_ERROR);
        bool hasDefaultRoute = false;
        for (ULONG i = 0; i < routes->NumEntries; ++i) {
            hasDefaultRoute |= routes->Table[i].DestinationPrefix.PrefixLength == 0;
        }
        ::FreeMibTable(routes);
        if (!hasDefaultRoute) {
            GTEST_SKIP() << "no default route for this socket family";
        }

        auto router = libxtun::Router::create();
        ASSERT_EQ(router->protectSocket(socket->native()), LIBXTUN_OK);

        DWORD ifindex = 0;
        int len = sizeof(ifindex);
        const int level = (family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
        const int option = (family == AF_INET) ? IP_UNICAST_IF : IPV6_UNICAST_IF;

        ASSERT_EQ(::getsockopt(libxtun::net::fromAbiDescriptor(socket->native()), level, option,
        reinterpret_cast<char *>(&ifindex), &len),
        0);
        EXPECT_NE(ifindex, 0u);
    }
    #endif
}

#if defined(_WIN32)
TEST(SocketProtection, ProtectsUnboundIpv4Socket)
{
    checkUnboundSocketProtection(AF_INET);
}

TEST(SocketProtection, ProtectsUnboundIpv6Socket)
{
    checkUnboundSocketProtection(AF_INET6);
}
#endif

TEST(SocketProtection, UnattachedAndDetachedIoReturnUnsupported)
{
    RecordingIo device;
    libxtun::AwaitingIo io;
    // No I/O device is attached yet
    EXPECT_EQ(io.protectSocket(42), LIBXTUN_ERR_UNSUPPORTED);

    io.assign(&device);
    // The I/O device is now attached
    EXPECT_EQ(io.protectSocket(42), LIBXTUN_OK);

    io.assign(nullptr);
    // The I/O device is detached again
    EXPECT_EQ(io.protectSocket(43), LIBXTUN_ERR_UNSUPPORTED);
    EXPECT_EQ(device.protectedSockets, std::vector<int> { 42 });
}

TEST(SocketProtection, HaltedIoReturnsUnsupported)
{
    RecordingIo device;
    libxtun::AwaitingIo io(&device);
    io.halt();

    EXPECT_EQ(io.protectSocket(42), LIBXTUN_ERR_UNSUPPORTED);
    EXPECT_TRUE(device.protectedSockets.empty());
}

TEST(SocketProtection, UserCallbackStillRunsAfterProtectionFails)
{
    RecordingIo device;
    device.result = LIBXTUN_ERR_SYSTEM;
    std::vector<int> notifiedSockets;
    libxtun::ClientCallbacks callbacks {
        .onSocket = [](int fd, void *priv) {
            static_cast<std::vector<int> *>(priv)->push_back(fd);
        },
        .onSocketPriv = &notifiedSockets
    };
    TestProxy proxy(callbacks);
    proxy.attachIo(&device);

    EXPECT_EQ(proxy.sockCb(42), LIBXTUN_ERR_SYSTEM);
    TestProxy::cSockCb(43, &proxy);

    EXPECT_EQ(device.protectedSockets, (std::vector<int> { 42, 43 }));
    EXPECT_EQ(notifiedSockets, device.protectedSockets);
}

TEST(SocketProtection, ClosedSocketReturnsSystemError)
{
    auto router = libxtun::Router::create();
    auto socket = libxtun::net::Socket::udp(AF_INET);
    ASSERT_TRUE(socket.has_value());
    const int fd = socket->native();
    socket.reset();

    EXPECT_EQ(router->protectSocket(fd), LIBXTUN_ERR_SYSTEM);
}
