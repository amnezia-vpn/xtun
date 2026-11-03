#include "proxy.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <mutex>
#include <stdexcept>
#include <string>

#if defined(__linux__) && !defined(__ANDROID__)
    #include "tunnel.h"
    #include "util/config.h"

    #include <cerrno>
    #include <cstdio>
    #include <cstdlib>
    #include <cstring>
    #include <fcntl.h>
    #include <sched.h>
    #include <unistd.h>
#endif

namespace
{
    using namespace std::chrono_literals;

    // No networking here: this class only publishes a profile.
    class ProfileProxy final : public libxtun::Proxy
    {
    public:
        explicit ProfileProxy(libxtun::ClientCallbacks callbacks = {}) : Proxy(callbacks)
        {
        }

        ~ProfileProxy() override
        {
            clearProfileListener();
            attachIo(nullptr);
        }

        const char *name() override
        {
            return "profile-test";
        }
        void event(libxtun::ProxyEvent) override
        {
        }

        void attachIo(libxtun::TunnelIo *io) override
        {
            Proxy::attachIo(io);
            if (io != nullptr && publishOnAttach) {
                attachStatus = publishProfile(profile());
            }
        }

        libxtun::ProxyProfile profile() const override
        {
            std::lock_guard<std::mutex> lock(m_profileMutex);
            return m_profile;
        }

        libxtun_error publish(const libxtun::ProxyProfile &profile)
        {
            {
                std::lock_guard<std::mutex> lock(m_profileMutex);
                m_profile = profile;
            }
            return publishProfile(profile);
        }

        using Proxy::publishProfile;
        bool publishOnAttach = false;
        libxtun_error attachStatus = LIBXTUN_ERR_UNSUPPORTED;

    private:
        mutable std::mutex m_profileMutex;
        libxtun::ProxyProfile m_profile;
    };

    class ProfileListener final : public libxtun::ProxyProfileListener
    {
    public:
        std::function<libxtun_error(libxtun::Proxy &, const libxtun::ProxyProfile &)> onChange;

        libxtun_error onProfileChanged(libxtun::Proxy &source, const libxtun::ProxyProfile &snapshot) override
        {
            return onChange(source, snapshot);
        }
    };
}

TEST(ProxyProfile, PassesSnapshotAndResult)
{
    // publishing with no listener leads to the error
    ProfileProxy proxy;
    libxtun::ProxyProfile current;
    current.routes = { *libxtun::net::IpPrefix::parse("198.51.100.0/24") };
    EXPECT_EQ(proxy.publish(current), LIBXTUN_ERR_UNSUPPORTED);

    // repeated listener registration is declined
    int calls = 0;
    ProfileListener listener;
    listener.onChange = [&](libxtun::Proxy &source, const libxtun::ProxyProfile &snapshot) {
        ++calls;
        EXPECT_EQ(&source, &proxy);
        EXPECT_EQ(snapshot.routes.size(), 1u);
        const auto current = source.profile();
        EXPECT_EQ(current.routes.size(), 1u);
        if (!snapshot.routes.empty() && !current.routes.empty()) {
            EXPECT_EQ(snapshot.routes.front().toString(), "203.0.113.0/24");
            EXPECT_EQ(current.routes.front().toString(), "198.51.100.0/24");
        }
        return LIBXTUN_ERR_SYSTEM;
    };
    ASSERT_EQ(proxy.setProfileListener(listener), LIBXTUN_OK);
    EXPECT_EQ(proxy.setProfileListener(listener), LIBXTUN_ERR_INVALID_ARGS);

    // listener.onChange() is really called
    auto snapshot = current;
    snapshot.routes = { *libxtun::net::IpPrefix::parse("203.0.113.0/24") };
    EXPECT_EQ(proxy.publishProfile(snapshot), LIBXTUN_ERR_SYSTEM);
    EXPECT_EQ(calls, 1);

    // there is no listener calls after unregistration
    proxy.clearProfileListener();
    EXPECT_EQ(proxy.publishProfile(snapshot), LIBXTUN_ERR_UNSUPPORTED);
    EXPECT_EQ(calls, 1);
}

TEST(ProxyProfile, ClearWaitsForListener)
{
    std::promise<void> listenerStarted;
    std::promise<void> finishListener;
    auto finishRequested = finishListener.get_future();
    ProfileProxy proxy;
    ProfileListener listener;
    listener.onChange = [&](libxtun::Proxy &, const libxtun::ProxyProfile &) {
        listenerStarted.set_value();
        const bool canFinish = finishRequested.wait_for(5s) == std::future_status::ready;
        EXPECT_TRUE(canFinish) << "The test did not allow the callback to finish";
        return canFinish ? LIBXTUN_OK : LIBXTUN_ERR_SYSTEM;
    };
    ASSERT_EQ(proxy.setProfileListener(listener), LIBXTUN_OK);

    // Start a publication. Its callback waits for permission to finish.
    auto publication = std::async(std::launch::async, [&]() { return proxy.publishProfile({}); });
    EXPECT_EQ(listenerStarted.get_future().wait_for(2s), std::future_status::ready);

    // Try to remove the listener. Removal must wait while the callback is still running.
    std::promise<void> clearStarted;
    auto clearing = std::async(std::launch::async, [&]() {
        clearStarted.set_value();
        proxy.clearProfileListener();
    });
    EXPECT_EQ(clearStarted.get_future().wait_for(2s), std::future_status::ready);
    EXPECT_EQ(clearing.wait_for(50ms), std::future_status::timeout);

    // Let the callback finish. Removal must complete, and later publications must not call the listener.
    finishListener.set_value();
    EXPECT_EQ(publication.get(), LIBXTUN_OK);
    clearing.get();
    EXPECT_EQ(proxy.publishProfile({}), LIBXTUN_ERR_UNSUPPORTED);
}

TEST(ProxyProfile, CallsListenerOneAtATime)
{
    std::promise<void> listenerStarted;
    std::promise<void> finishListener;
    auto finishRequested = finishListener.get_future();
    std::atomic<int> calls { 0 };
    ProfileProxy proxy;
    ProfileListener listener;
    listener.onChange = [&](libxtun::Proxy &, const libxtun::ProxyProfile &) {
        if (++calls == 1) {
            listenerStarted.set_value();
            const bool canFinish = finishRequested.wait_for(5s) == std::future_status::ready;
            EXPECT_TRUE(canFinish) << "The test did not allow the callback to finish";
            return canFinish ? LIBXTUN_OK : LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    };
    ASSERT_EQ(proxy.setProfileListener(listener), LIBXTUN_OK);

    // Start the first publication and keep its callback waiting.
    auto first = std::async(std::launch::async, [&]() { return proxy.publishProfile({}); });
    EXPECT_EQ(listenerStarted.get_future().wait_for(2s), std::future_status::ready);

    // Start a second publication. It must wait without calling the listener again yet.
    std::promise<void> secondStarted;
    auto second = std::async(std::launch::async, [&]() {
        secondStarted.set_value();
        return proxy.publishProfile({});
    });
    EXPECT_EQ(secondStarted.get_future().wait_for(2s), std::future_status::ready);
    EXPECT_EQ(second.wait_for(50ms), std::future_status::timeout);
    EXPECT_EQ(calls.load(), 1);

    // Let the first callback finish. Both publications must succeed, with two listener calls in total.
    finishListener.set_value();
    EXPECT_EQ(first.get(), LIBXTUN_OK);
    EXPECT_EQ(second.get(), LIBXTUN_OK);
    EXPECT_EQ(calls.load(), 2);
    proxy.clearProfileListener();
}

TEST(ProxyProfile, ReturnsErrorOnException)
{
    // If the listener throws an exception, publishProfile() must call onLog() and return LIBXTUN_ERR_SYSTEM.
    // If onLog() throws an exception too, publishProfile() must catch it and return the same error.
    std::string message;
    libxtun::ClientCallbacks callbacks {
        .onLog = [](const char *text, void *priv) {
            *static_cast<std::string *>(priv) = text;
            throw std::runtime_error("log failure");
        },
        .onLogPriv = &message
    };
    ProfileProxy proxy(callbacks);
    ProfileListener listener;
    listener.onChange = [](libxtun::Proxy &, const libxtun::ProxyProfile &) -> libxtun_error {
        throw std::runtime_error("listener failure");
    };
    ASSERT_EQ(proxy.setProfileListener(listener), LIBXTUN_OK);
    EXPECT_EQ(proxy.publishProfile({}), LIBXTUN_ERR_SYSTEM);
    EXPECT_EQ(message, "xtun: profile listener threw an unexpected exception");

    message.clear();
    listener.onChange = [](libxtun::Proxy &, const libxtun::ProxyProfile &) { return LIBXTUN_ERR_SYSTEM; };
    EXPECT_EQ(proxy.publishProfile({}), LIBXTUN_ERR_SYSTEM);
    EXPECT_TRUE(message.empty());

    listener.onChange = [](libxtun::Proxy &, const libxtun::ProxyProfile &) { return LIBXTUN_OK; };
    EXPECT_EQ(proxy.publishProfile({}), LIBXTUN_OK);
    EXPECT_TRUE(message.empty());
    proxy.clearProfileListener();
    EXPECT_EQ(proxy.publishProfile({}), LIBXTUN_ERR_UNSUPPORTED);
}

#if defined(__linux__) && !defined(__ANDROID__)
namespace
{
    class LinuxTunnelProfileTest : public testing::Test
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
            ASSERT_EQ(std::system("ip link set lo up"), 0);
            libxtun::test::TunOpts opts;
            opts.ifaddrs({ "10.99.0.2/24" }).mtu(1400);
            auto result = libxtun::Tunnel::fromOpts(opts.get());
            ASSERT_TRUE(result) << result.error();
            m_tunnel = std::move(result).value();
        }

        void TearDown() override
        {
            m_tunnel.reset();
            if (m_inNetns) {
                EXPECT_EQ(::setns(m_originalNetns, CLONE_NEWNET), 0) << std::strerror(errno);
            }
            if (m_originalNetns >= 0) {
                ::close(m_originalNetns);
            }
        }

        libxtun::ProxyProfile sessionProfile() const
        {
            libxtun::ProxyProfile profile;
            profile.routes = { *libxtun::net::IpPrefix::parse("198.51.100.0/24") };
            return profile;
        }

        std::vector<std::string> addresses() const
        {
            std::vector<std::string> result;
            for (const auto &prefix : m_tunnel->addresses()) {
                result.push_back(prefix.toString());
            }
            return result;
        }

        std::string routes(int family = AF_INET) const
        {
            const auto command = std::string(family == AF_INET ? "ip -4 route show dev " : "ip -6 route show dev ")
                    + m_tunnel->name();
            FILE *pipe = ::popen(command.c_str(), "r");
            if (pipe == nullptr) {
                ADD_FAILURE() << "could not run " << command;
                return {};
            }
            char buffer[512];
            std::string result;
            while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                result += buffer;
            }
            EXPECT_EQ(::pclose(pipe), 0);
            return result;
        }

        ProfileProxy m_proxy;
        ProfileProxy m_otherProxy;
        std::unique_ptr<libxtun::Tunnel> m_tunnel;

    private:
        int m_originalNetns = -1;
        bool m_inNetns = false;
    };
}

TEST_F(LinuxTunnelProfileTest, AppliesProfileOnAttach)
{
    const auto profile = sessionProfile();
    EXPECT_EQ(m_proxy.publish(profile), LIBXTUN_ERR_UNSUPPORTED);
    m_proxy.publishOnAttach = true;
    ASSERT_EQ(m_tunnel->attachProxy(&m_proxy), LIBXTUN_OK);
    EXPECT_EQ(m_proxy.attachStatus, LIBXTUN_OK);
    EXPECT_EQ(addresses(), std::vector<std::string> { "10.99.0.2/24" });
    EXPECT_EQ(m_tunnel->mtu(), 1400);
    EXPECT_NE(routes().find("198.51.100.0/24"), std::string::npos);

    ASSERT_EQ(m_tunnel->detachProxy(&m_proxy), LIBXTUN_OK);
    EXPECT_EQ(addresses(), std::vector<std::string> { "10.99.0.2/24" });
    EXPECT_EQ(m_tunnel->mtu(), 1400);
    EXPECT_EQ(routes().find("198.51.100.0/24"), std::string::npos);
    EXPECT_EQ(m_proxy.publish(profile), LIBXTUN_ERR_UNSUPPORTED);
}

TEST_F(LinuxTunnelProfileTest, ReplacesRoutesWithoutChangingInterface)
{
    ASSERT_EQ(m_tunnel->attachProxy(&m_proxy), LIBXTUN_OK);
    auto profile = sessionProfile();
    ASSERT_EQ(m_proxy.publish(profile), LIBXTUN_OK);

    profile.routes = { *libxtun::net::IpPrefix::parse("203.0.113.0/24") };
    ASSERT_EQ(m_proxy.publish(profile), LIBXTUN_OK);
    EXPECT_EQ(addresses(), std::vector<std::string> { "10.99.0.2/24" });
    EXPECT_EQ(m_tunnel->mtu(), 1400);
    EXPECT_EQ(routes().find("198.51.100.0/24"), std::string::npos);
    EXPECT_NE(routes().find("203.0.113.0/24"), std::string::npos);
}

TEST_F(LinuxTunnelProfileTest, ReplacesRoutesOnProxyReplacement)
{
    ASSERT_EQ(m_tunnel->attachProxy(&m_proxy), LIBXTUN_OK);
    const auto profile = sessionProfile();
    ASSERT_EQ(m_proxy.publish(profile), LIBXTUN_OK);

    libxtun::ProxyProfile legacyProfile;
    legacyProfile.routes = { *libxtun::net::IpPrefix::parse("203.0.113.0/24") };
    EXPECT_EQ(m_otherProxy.publish(legacyProfile), LIBXTUN_ERR_UNSUPPORTED);
    ASSERT_EQ(m_tunnel->attachProxy(&m_otherProxy), LIBXTUN_OK);
    EXPECT_EQ(addresses(), std::vector<std::string> { "10.99.0.2/24" });
    EXPECT_EQ(m_tunnel->mtu(), 1400);
    EXPECT_EQ(m_proxy.publish(profile), LIBXTUN_ERR_UNSUPPORTED);
    EXPECT_EQ(routes().find("198.51.100.0/24"), std::string::npos);
    EXPECT_NE(routes().find("203.0.113.0/24"), std::string::npos);
}

TEST_F(LinuxTunnelProfileTest, ClearsListenerOnDestroy)
{
    ASSERT_EQ(m_tunnel->attachProxy(&m_proxy), LIBXTUN_OK);
    const auto profile = sessionProfile();
    ASSERT_EQ(m_proxy.publish(profile), LIBXTUN_OK);
    m_tunnel.reset();
    EXPECT_EQ(m_proxy.publish(profile), LIBXTUN_ERR_UNSUPPORTED);
}

TEST_F(LinuxTunnelProfileTest, ClearsIpv6RoutesOnDetach)
{
    libxtun::ProxyProfile legacy;
    legacy.routes = { *libxtun::net::IpPrefix::parse("2001:db8:48::/64") };
    EXPECT_EQ(m_proxy.publish(legacy), LIBXTUN_ERR_UNSUPPORTED);
    ASSERT_EQ(m_tunnel->attachProxy(&m_proxy), LIBXTUN_OK);
    ASSERT_NE(routes(AF_INET6).find("2001:db8:48::/64"), std::string::npos);

    ASSERT_EQ(m_proxy.publish(sessionProfile()), LIBXTUN_OK);
    ASSERT_EQ(m_tunnel->detachProxy(&m_proxy), LIBXTUN_OK);
    EXPECT_EQ(routes(AF_INET6).find("2001:db8:48::/64"), std::string::npos);
    EXPECT_EQ(addresses(), std::vector<std::string> { "10.99.0.2/24" });
}

TEST_F(LinuxTunnelProfileTest, ReportsRouteFailureWithoutChangingInterface)
{
    ASSERT_EQ(m_tunnel->attachProxy(&m_proxy), LIBXTUN_OK);
    ASSERT_EQ(std::system("ip route add 198.51.100.0/24 dev lo"), 0);
    EXPECT_EQ(m_proxy.publish(sessionProfile()), LIBXTUN_ERR_SYSTEM);
    EXPECT_EQ(addresses(), std::vector<std::string> { "10.99.0.2/24" });
    EXPECT_EQ(m_tunnel->mtu(), 1400);
    EXPECT_EQ(routes().find("198.51.100.0/24"), std::string::npos);
    ASSERT_EQ(m_tunnel->detachProxy(&m_proxy), LIBXTUN_OK);
}

#endif
