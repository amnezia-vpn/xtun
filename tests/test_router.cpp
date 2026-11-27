#include "net/ip.h"
#include "router.h"
#include "xtun.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace libxtun;

namespace
{
    class IgnoredUplink final : public RouterListener
    {
    public:
        void onUplinkChanged() override
        {
        }
    };

    IgnoredUplink g_ignoredUplink;

    class CountingRouter final : public Router
    {
    public:
        CountingRouter() : Router(g_ignoredUplink)
        {
        }

        int adds = 0;
        int removes = 0;
        libxtun_error addResult = LIBXTUN_OK;

        libxtun_error configureInterface(const std::string &, int, const std::vector<net::IpPrefix> &) override
        {
            return LIBXTUN_OK;
        }
        libxtun_error setMtu(int) override
        {
            return LIBXTUN_OK;
        }
        void revert() override
        {
        }
        void protectSocket(int) override
        {
        }

    protected:
        libxtun_error addProxyRoutes(const std::vector<net::IpPrefix> &, const std::vector<net::IpPrefix> &) override
        {
            ++adds;
            return addResult;
        }

        void removeProxyRoutes() override
        {
            ++removes;
        }
    };
}

TEST(Router, EqualSetChangesNothing)
{
    CountingRouter router;
    const std::vector<net::IpPrefix> routesA { *net::IpPrefix::parse("10.0.0.0/8") };
    const std::vector<net::IpPrefix> routesB { *net::IpPrefix::parse("192.168.0.0/16") };
    const std::vector<net::IpPrefix> excludes { *net::IpPrefix::parse("10.1.0.0/16") };

    ASSERT_EQ(router.setProxyRoutes(routesA, excludes), LIBXTUN_OK);
    ASSERT_EQ(router.setProxyRoutes(routesA, excludes), LIBXTUN_OK);
    EXPECT_EQ(router.adds, 1) << "an equal set was applied again";

    int removed = router.removes;
    ASSERT_EQ(router.setProxyRoutes(routesB, excludes), LIBXTUN_OK);
    EXPECT_EQ(router.adds, 2);
    EXPECT_EQ(router.removes, removed + 1) << "a different set was not applied over a clean state";

    removed = router.removes;
    ASSERT_EQ(router.setProxyRoutes(routesB, {}), LIBXTUN_OK);
    EXPECT_EQ(router.adds, 3) << "a set that differs only in its excludes was kept";
    EXPECT_EQ(router.removes, removed + 1);

    router.clearProxyRoutes();
    ASSERT_EQ(router.setProxyRoutes(routesB, {}), LIBXTUN_OK);
    EXPECT_EQ(router.adds, 4) << "a cleared set counted as applied";

    router.addResult = LIBXTUN_ERR_SYSTEM;
    EXPECT_EQ(router.setProxyRoutes(routesA, excludes), LIBXTUN_ERR_SYSTEM);
    router.addResult = LIBXTUN_OK;
    ASSERT_EQ(router.setProxyRoutes(routesA, excludes), LIBXTUN_OK);
    EXPECT_EQ(router.adds, 6) << "a failed set counted as applied";
}
