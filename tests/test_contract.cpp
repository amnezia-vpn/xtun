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
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, NewRejectsOutOfRangeKillswitch)
{
    libxtun::test::TunOpts opts;
    libxtun_tunnel tun;
    opts.killswitchMode(static_cast<libxtun_killswitch_mode>(LIBXTUN_KILLSWITCH_MODE_LAST + 1));
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FromFdRejectsNullTunnel)
{
    for (int fd : { 0, -1 }) {
        EXPECT_EQ(libxtun_tunnel_new_from_tunfile(nullptr, fd), LIBXTUN_ERR_INVALID_ARGS);
    }
}

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

TEST(ContractTunnel, IgnoresNull)
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
