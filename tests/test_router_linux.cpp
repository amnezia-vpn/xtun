#if defined(__linux__) && !defined(__ANDROID__)

    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
    #endif

    #include "fwmark.h"
    #include "killswitch.h"
    #include "router.h"
    #include "tun_device.h"
    #include "util/os.h"

    #include <gtest/gtest.h>

    #include <cerrno>
    #include <cstdio>
    #include <cstdlib>
    #include <cstring>
    #include <fcntl.h>
    #include <memory>
    #include <sched.h>
    #include <string>
    #include <unistd.h>

namespace
{
    bool runIp(const std::string &args)
    {
        return std::system(("ip " + args).c_str()) == 0;
    }

    std::string ipOutput(const std::string &args)
    {
        const auto command = "ip " + args + " 2>&1";
        FILE *pipe = ::popen(command.c_str(), "r");
        if (pipe == nullptr) {
            ADD_FAILURE() << "could not run " << command;
            return {};
        }
        char buffer[512];
        std::string output;
        while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        const int rc = ::pclose(pipe);
        if (rc != 0) {
            ADD_FAILURE() << command << " failed: " << output;
        }
        return output;
    }

    class LinuxRouterTest : public testing::Test
    {
    protected:
        void SetUp() override
        {
            if (::geteuid() != 0) {
                GTEST_SKIP() << "requires root to create an isolated network namespace and configure TUN";
            }
            m_originalNetns = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
            ASSERT_GE(m_originalNetns, 0);
            if (::unshare(CLONE_NEWNET) != 0) {
                GTEST_SKIP() << "cannot create a network namespace: " << std::strerror(errno);
            }
            m_inNetns = true;
            if (::access("/dev/net/tun", R_OK | W_OK) != 0) {
                GTEST_SKIP() << "/dev/net/tun is not available";
            }
            ASSERT_TRUE(runIp("link set lo up")) << "requires iproute2";
            m_device = libxtun::createTunDevice();
            ASSERT_NE(m_device, nullptr);
            ASSERT_EQ(m_device->open(), LIBXTUN_OK);
            m_router = libxtun::Router::create();
            ASSERT_NE(m_router, nullptr);
            ASSERT_EQ(m_router->configureInterface(m_device->name(), m_device->ifIndex(), { "10.99.0.2/24" }, 1400),
                      LIBXTUN_OK);
        }

        void TearDown() override
        {
            if (m_router) {
                m_router->revert();
                m_router.reset();
            }
            m_device.reset();
            if (m_inNetns) {
                EXPECT_EQ(::setns(m_originalNetns, CLONE_NEWNET), 0) << std::strerror(errno);
            }
            if (m_originalNetns >= 0) {
                ::close(m_originalNetns);
            }
        }

        std::string addresses(int family = AF_INET) const
        {
            return ipOutput(std::string(family == AF_INET ? "-4" : "-6") + " -o address show dev " + m_device->name());
        }

        std::string routes(int family = AF_INET) const
        {
            return ipOutput(std::string(family == AF_INET ? "-4" : "-6") + " -o route show table all dev "
                            + m_device->name() + " proto boot");
        }

        std::unique_ptr<libxtun::TunDevice> m_device;
        std::unique_ptr<libxtun::Router> m_router;

    private:
        int m_originalNetns = -1;
        bool m_inNetns = false;
    };
}

TEST_F(LinuxRouterTest, ClearsRoutesWithoutChangingInterface)
{
    const auto initialAddresses = addresses();
    const int initialMtu = m_device->mtu();
    ASSERT_EQ(m_router->setProxyRoutes({ "198.51.100.0/24", "0.0.0.0/0" }), LIBXTUN_OK);
    EXPECT_NE(routes().find("198.51.100.0/24"), std::string::npos);
    EXPECT_NE(routes().find("default"), std::string::npos);

    ASSERT_EQ(m_router->clearProxyRoutes(), LIBXTUN_OK);
    EXPECT_TRUE(routes().empty());
    EXPECT_EQ(addresses(), initialAddresses);
    EXPECT_EQ(m_device->mtu(), initialMtu);
}

TEST_F(LinuxRouterTest, FullTunnelKeepsMarkedTrafficAndLanOnThePhysicalRoute)
{
    ASSERT_TRUE(runIp("link add physical0 type dummy"));
    ASSERT_TRUE(runIp("address add 192.0.2.2/24 dev physical0"));
    ASSERT_TRUE(runIp("link set physical0 up"));
    ASSERT_TRUE(runIp("route add default via 192.0.2.1 dev physical0"));
    ASSERT_EQ(m_router->setProxyRoutes({ "0.0.0.0/0" }), LIBXTUN_OK);
    const auto rules = ipOutput("-4 rule show");

    EXPECT_NE(ipOutput("-4 route get 8.8.8.8").find("dev " + m_device->name()), std::string::npos);
    EXPECT_NE(ipOutput("-4 route get 8.8.8.8 mark " + std::to_string(libxtun::PROXY_FWMARK)).find("dev physical0"),
              std::string::npos);
    EXPECT_NE(ipOutput("-4 route get 192.0.2.40").find("dev physical0"), std::string::npos);
    ASSERT_EQ(m_router->setProxyRoutes({ "0.0.0.0/0" }), LIBXTUN_OK);
    EXPECT_EQ(ipOutput("-4 rule show"), rules);

    ASSERT_EQ(m_router->clearProxyRoutes(), LIBXTUN_OK);
    EXPECT_EQ(ipOutput("-4 rule show").find(std::to_string(libxtun::RULE_PRIORITY_TUNNEL) + ":"), std::string::npos);
    EXPECT_EQ(ipOutput("-4 rule show").find(std::to_string(libxtun::RULE_PRIORITY_LAN) + ":"), std::string::npos);
    EXPECT_NE(ipOutput("-4 route get 8.8.8.8").find("dev physical0"), std::string::npos);
    EXPECT_EQ(m_device->mtu(), 1400);
}

TEST_F(LinuxRouterTest, FullTunnelWorksWithKillswitchInstalledFirstAndBlocksWhenRoutesAreLost)
{
    ASSERT_TRUE(runIp("link add physical0 type dummy"));
    ASSERT_TRUE(runIp("address add 192.0.2.2/24 dev physical0"));
    ASSERT_TRUE(runIp("link set physical0 up"));
    ASSERT_TRUE(runIp("route add default via 192.0.2.1 dev physical0"));
    const auto sendPacket = [](unsigned mark) {
        auto [socket, error] = libxtun::test::udpConnect("8.8.8.8", 443, mark);
        if (error != 0) {
            return error;
        }
        const char byte = 0;
        return ::send(socket.get(), &byte, 1, MSG_DONTWAIT) == 1 ? 0 : errno;
    };
    ASSERT_EQ(sendPacket(0), 0);

    auto killswitch = libxtun::Killswitch::create(LIBXTUN_KILLSWITCH_MODE_SOFT);
    ASSERT_NE(killswitch, nullptr);
    ASSERT_EQ(killswitch->update(m_device->ifIndex(), m_device->name()), LIBXTUN_OK);
    const auto defaultRoute = libxtun::net::IpPrefix::parse("0.0.0.0/0");
    ASSERT_TRUE(defaultRoute);
    ASSERT_EQ(killswitch->protect({ *defaultRoute }), LIBXTUN_OK);
    EXPECT_EQ(sendPacket(0), EPERM);
    const auto killswitchRules = ipOutput("-4 rule show");

    ASSERT_EQ(m_router->setProxyRoutes({ "0.0.0.0/0" }), LIBXTUN_OK);
    EXPECT_NE(ipOutput("-4 route get 8.8.8.8").find("dev " + m_device->name()), std::string::npos);
    EXPECT_EQ(sendPacket(0), 0);
    EXPECT_NE(ipOutput("-4 route get 8.8.8.8 mark " + std::to_string(libxtun::PROXY_FWMARK)).find("dev physical0"),
              std::string::npos);
    EXPECT_NE(ipOutput("-4 route get 192.0.2.40").find("dev physical0"), std::string::npos);

    ASSERT_EQ(m_router->clearProxyRoutes(), LIBXTUN_OK);
    EXPECT_EQ(ipOutput("-4 rule show"), killswitchRules);
    EXPECT_NE(ipOutput("-4 route get 8.8.8.8").find("dev physical0"), std::string::npos);
    EXPECT_EQ(sendPacket(0), EPERM);
    EXPECT_NE(ipOutput("-4 route get 8.8.8.8 mark " + std::to_string(libxtun::PROXY_FWMARK)).find("dev physical0"),
              std::string::npos);
    EXPECT_EQ(sendPacket(libxtun::PROXY_FWMARK), 0);

    ASSERT_EQ(killswitch->protect({}), LIBXTUN_OK);
    EXPECT_EQ(sendPacket(0), 0);
}

TEST_F(LinuxRouterTest, FailedRouteSetupKeepsForeignRouteAndRemovesCreatedRoutes)
{
    ASSERT_TRUE(runIp("-4 route add 203.0.113.0/24 dev lo"));
    const auto externalRoutes = ipOutput("-4 route show dev lo");
    EXPECT_EQ(m_router->setProxyRoutes({ "198.51.100.0/24", "203.0.113.0/24" }), LIBXTUN_ERR_SYSTEM);
    EXPECT_TRUE(routes().empty());
    EXPECT_EQ(ipOutput("-4 route show dev lo"), externalRoutes);
    EXPECT_NE(addresses().find("10.99.0.2/24"), std::string::npos);
    EXPECT_EQ(m_device->mtu(), 1400);
}

TEST_F(LinuxRouterTest, FailedFullTunnelSetupRemovesCreatedPartsButKeepsForeignRule)
{
    const auto command = "-4 rule add priority " + std::to_string(libxtun::RULE_PRIORITY_LAN)
            + " lookup main suppress_prefixlength 0";
    ASSERT_TRUE(runIp(command));
    const auto externalRules = ipOutput("-4 rule show");

    EXPECT_EQ(m_router->setProxyRoutes({ "0.0.0.0/0" }), LIBXTUN_ERR_SYSTEM);
    EXPECT_TRUE(routes().empty());
    EXPECT_EQ(ipOutput("-4 rule show"), externalRules);
    ASSERT_EQ(m_router->clearProxyRoutes(), LIBXTUN_OK);
    EXPECT_EQ(ipOutput("-4 rule show"), externalRules);
}

TEST_F(LinuxRouterTest, ExistingPrivateTableRouteIsNotReplacedOrRemoved)
{
    ASSERT_TRUE(runIp("-4 route add default dev lo table " + std::to_string(libxtun::PROXY_TABLE)));
    const auto externalRoutes = ipOutput("-4 route show table all dev lo");
    EXPECT_EQ(m_router->setProxyRoutes({ "0.0.0.0/0" }), LIBXTUN_ERR_SYSTEM);
    ASSERT_EQ(m_router->clearProxyRoutes(), LIBXTUN_OK);
    EXPECT_EQ(ipOutput("-4 route show table all dev lo"), externalRoutes);
}

TEST_F(LinuxRouterTest, RejectsInvalidRoutesWithoutChangingInterface)
{
    const auto initialAddresses = addresses();
    EXPECT_EQ(m_router->setProxyRoutes({ "198.51.100.0/24", "not-a-route" }), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_TRUE(routes().empty());
    EXPECT_EQ(addresses(), initialAddresses);
    EXPECT_EQ(m_device->mtu(), 1400);
}

TEST_F(LinuxRouterTest, ClearsBothRouteFamiliesWithoutChangingAddresses)
{
    ASSERT_EQ(m_router->configureInterface(m_device->name(), m_device->ifIndex(), { "10.99.0.2/24", "fd00::2/64" },
                                          1400),
              LIBXTUN_OK);
    const auto initialV4 = addresses(AF_INET);
    const auto initialV6 = addresses(AF_INET6);
    ASSERT_EQ(m_router->setProxyRoutes({ "198.51.100.0/24", "0.0.0.0/0", "2001:db8::/32", "::/0" }), LIBXTUN_OK);
    ASSERT_EQ(m_router->clearProxyRoutes(), LIBXTUN_OK);
    EXPECT_TRUE(routes(AF_INET).empty());
    EXPECT_TRUE(routes(AF_INET6).empty());
    EXPECT_EQ(addresses(AF_INET), initialV4);
    EXPECT_EQ(addresses(AF_INET6), initialV6);
    EXPECT_EQ(m_device->mtu(), 1400);
}

#endif
