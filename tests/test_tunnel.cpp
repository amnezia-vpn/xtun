#include "mock/memproxy.h"
#include "tunnel.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "xtun.h"

#include "gtest/gtest.h"
#include <gtest/gtest.h>

using namespace libxtun;

class TunnelTestBase : public testing::Test
{
public:
    void SetUp() override
    {
        if (!test::privileged()) {
            GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
        }
    }
};

class TunnelTestOpts : public TunnelTestBase
{
};

TEST_F(TunnelTestOpts, AttachesProxy)
{
    test::Logger log;
    test::TunOpts opts;
    test::MemProxy proxy(log.defaultCallbacks());

    auto res = Tunnel::fromOpts(opts.get());
    EXPECT_TRUE(res) << "Tunnel::fromOpts failed with " << res.error() << " error code";
    auto &tunnel = res.value();

    EXPECT_EQ(tunnel->attachProxy(&proxy), 0);
}

#ifndef WIN32
class TunnelTestTunfactory : public TunnelTestBase
{
};

TEST_F(TunnelTestTunfactory, RejectsInvalidFactory)
{
    test::Logger log;
    test::MemProxy proxy(log.defaultCallbacks());

    auto res = Tunnel::fromTunfactory(nullptr, {});
    ASSERT_FALSE(res);
    ASSERT_EQ(res.error(), LIBXTUN_ERR_INVALID_ARGS);
}

TEST_F(TunnelTestTunfactory, AttachesProxy)
{
    test::Logger log;
    test::MemProxy proxy(log.defaultCallbacks());

    auto res = Tunnel::fromTunfactory(
            [&](const std::vector<net::IpAddress> &dns, const std::vector<net::IpPrefix> &routes, int mtu) {
                auto tun = libxtun::test::createTun();
                if (!tun) {
                    return -1;
                }
                return tun->first.release();
            },
            { "10.0.0.1" });
    EXPECT_TRUE(res) << "Tunnel::fromTunfactory failed with " << res.error() << " error code";
    auto &tunnel = res.value();

    EXPECT_EQ(tunnel->attachProxy(&proxy), 0);
}
#endif // WIN32
