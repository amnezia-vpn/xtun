#include "xtun.h"

#include <gtest/gtest.h>

#include <string>

#if defined(__linux__) || defined(__APPLE__)
    #include <fcntl.h>
    #include <unistd.h>
#endif

#if defined(__linux__)
    #include <linux/if.h>
#endif

namespace
{

    libxtun_tunnel_opts defaultOpts()
    {
        libxtun_tunnel_opts opts {};
        opts.size = sizeof(opts);
        opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        return opts;
    }

} // namespace

TEST(TunnelNew, RejectsNullTunnel)
{
    libxtun_tunnel_opts opts = defaultOpts();
    EXPECT_EQ(libxtun_tunnel_new(nullptr, &opts), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelNew, RejectsNullOpts)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelNew, RejectsUndersizedOpts)
{
    libxtun_tunnel tun;
    libxtun_tunnel_opts opts = defaultOpts();
    opts.size = sizeof(opts) - 1;
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts), LIBXTUN_ERR_INVALID_ARGS);
    EXPECT_EQ(tun.handle, nullptr);
}

TEST(TunnelNew, RejectsOutOfRangeKillswitch)
{
    libxtun_tunnel tun;
    libxtun_tunnel_opts opts = defaultOpts();
    opts.killswitch_mode = static_cast<libxtun_killswitch_mode>(LIBXTUN_KILLSWITCH_MODE_LAST + 1);
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromFd, RejectsNullTunnel)
{
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(nullptr, 0), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromFd, RejectsNegativeFd)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(&tun, -1), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromName, RejectsNullTunnel)
{
    EXPECT_EQ(libxtun_tunnel_new_from_name(nullptr, "xtun"), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromName, RejectsNullName)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromName, RejectsEmptyName)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, ""), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFree, IgnoresNull)
{
    libxtun_tunnel_free(nullptr);
}

#if defined(__linux__) || defined(__APPLE__)

TEST(TunnelFromFd, RejectsClosedFd)
{
    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    ::close(fds[0]);
    ::close(fds[1]);

    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(&tun, fds[0]), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromFd, RejectsNonTunFd)
{
    int fd = ::open("/dev/null", O_RDWR);
    ASSERT_GE(fd, 0);

    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(&tun, fd), LIBXTUN_ERR_DEVICE_CREATE);
    ::close(fd);
}

#endif

#if defined(__linux__)

TEST(TunnelFromName, RejectsOverlongName)
{
    libxtun_tunnel tun;
    std::string name(IFNAMSIZ + 4, 'x');
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, name.c_str()), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(TunnelFromName, RejectsNonexistentDevice)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, "xtun_nope0"), LIBXTUN_ERR_DEVICE_CREATE);
}

#endif

#if defined(_WIN32)

TEST(TunnelFromFd, UnsupportedOnWindows)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_tunfile(&tun, 0), LIBXTUN_ERR_DRIVER_UNAVAILABLE);
}

#endif

#if defined(__APPLE__)

TEST(TunnelFromName, UnsupportedOnMac)
{
    libxtun_tunnel tun;
    EXPECT_EQ(libxtun_tunnel_new_from_name(&tun, "utun0"), LIBXTUN_ERR_DRIVER_UNAVAILABLE);
}

#endif
