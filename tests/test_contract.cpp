#include "mock/memtun.h"
#include "proxy.h"
#include "util/config.h"
#include "util/log.h"
#include "xtun.h"
#include "gtest/gtest.h"
#include <gtest/gtest.h>

TEST(ContractTunnel, NewRejectsNullTunnel)
{
    libxtun::test::TunOpts opts;
    EXPECT_EQ(libxtun_tunnel_new(nullptr, &opts.get()), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, NewRejectsNullOpts)
{
    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, NewRejectsOutOfRangeKillswitch)
{
    libxtun::test::TunOpts opts;
    opts.killswitchMode(static_cast<libxtun_killswitch_mode>(LIBXTUN_KILLSWITCH_MODE_LAST + 1));

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_ERR_INVALID_ARGS);
}

class ContractTunnelFd : public testing::TestWithParam<int>
{
};

TEST_P(ContractTunnelFd, FromFdRejectsInvalid)
{
    auto fd = GetParam();
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(nullptr, fd), LIBXTUN_ERR_INVALID_ARGS);
}

INSTANTIATE_TEST_SUITE_P(ContractTunnel, ContractTunnelFd, testing::Values(0, -1));

TEST(ContractTunnel, FromFdRejectsNegativeFd)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(&tun, -1), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FromNameRejectsNullTunnel)
{
    EXPECT_EQ(libxtun_tunnel_new_from_name(nullptr, "xtun"), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FromNameRejectsNullName)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FromNameRejectsEmptyName)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, ""), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FreeIgnoresNull)
{
    libxtun_tunnel_free(nullptr);
}

TEST(ContractTunnel, FromNameRejectsOverlongName)
{
    libxtun_tunnel tun;
    std::string name(512, 'x');

    int res = libxtun_tunnel_new_from_name(&tun, name.c_str());
    if (res == LIBXTUN_ERR_UNSUPPORTED) {
        GTEST_SKIP() << "skipped due to unsupported named tunnels";
    }
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FromNameRejectsNonexistentDevice)
{
    libxtun_tunnel tun;

    int res = libxtun_tunnel_new_from_name(&tun, "xtun_nope0");
    if (res == LIBXTUN_ERR_UNSUPPORTED) {
        GTEST_SKIP() << "skipped due to unsupported named tunnels";
    }
    EXPECT_EQ(res, LIBXTUN_ERR_DEVICE_CREATE);
}

TEST(ContractProxy, FreeIgnoresNull)
{
    libxtun_proxy_free(nullptr);
}

TEST(ContractProxy, NewRejectsOutOfRangeProto)
{
    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, static_cast<libxtun_proxy_proto>(LIBXTUN_PROXY_PROTO_LAST + 1), "");
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
}

class ContractProxyProto : public testing::TestWithParam<libxtun_proxy_proto>
{
};

TEST_P(ContractProxyProto, NewRejectsNullHandle)
{
    const libxtun_proxy_proto proto = GetParam();

    int res = libxtun_proxy_new(nullptr, proto, nullptr);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
}

TEST_P(ContractProxyProto, NewRejectsNullConf)
{
    const libxtun_proxy_proto proto = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, proto, nullptr);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
}

TEST_P(ContractProxyProto, NewRejectsInvalidConf)
{
    const libxtun_proxy_proto proto = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, proto, "d34db33f");
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
}

INSTANTIATE_TEST_SUITE_P(ContractProxy, ContractProxyProto, testing::ValuesIn(libxtun::test::allProtos()));

class ContractProxyConfpair : public testing::TestWithParam<libxtun::test::Confpair>
{
};

TEST_P(ContractProxyConfpair, InitsFromConf)
{
    const auto &[_a, proto, conf, _b, _c] = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, proto, conf.c_str());
    EXPECT_EQ(res, 0);
}

TEST_P(ContractProxyConfpair, )
{
}

INSTANTIATE_TEST_SUITE_P(ContractProxy, ContractProxyConfpair,
                         testing::ValuesIn(libxtun::test::ConfpairBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Confpair> &info) { return info.param.name; });