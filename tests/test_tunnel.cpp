#include "mock/memproxy.h"
#include "tunnel.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"

#include <gtest/gtest.h>

TEST(Tunnel, InitializesFromOpts)
{
    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }

    std::string name;
    libxtun::test::TunOpts opts;
    {
        auto res = libxtun::Tunnel::fromOpts(opts.get());
        EXPECT_TRUE(res) << "Tunnel::fromOpts failed with " << res.error() << " error code";

        auto &tun = res.value();
        name = tun->name();

        if (auto exist = libxtun::test::ifaceExists(name)) {
            EXPECT_TRUE(*exist) << "created iface does not exist";
        }
    }

    if (auto exist = libxtun::test::ifaceExists(name)) {
        EXPECT_FALSE(*exist) << "iface did not destroyed after Tunnel end of life";
    }
}

TEST(Tunnel, InitializesFromFd)
{
    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }

    if (auto tun = libxtun::test::createTun()) {
        auto &[fd, name] = *tun;
        EXPECT_TRUE(fd) << "test::createTun returned " << fd.get();

        auto res = libxtun::Tunnel::fromFd(fd.get());
        EXPECT_TRUE(res) << "Tunnel::fromFd failed with " << res.error() << " error code";

        if (auto exist = libxtun::test::ifaceExists(name)) {
            EXPECT_TRUE(*exist) << "fd does not exist after tunnel init";
        }
    } else {
        GTEST_SKIP() << "fd TUNs are not supported on this platform";
    }
}

TEST(Tunnel, RejectsInvalidFd)
{
    for (int fd : { 0, -1 }) {
        auto res = libxtun::Tunnel::fromFd(0);
        if (!res && res.error() == LIBXTUN_ERR_UNSUPPORTED) {
            GTEST_SKIP() << "skipping test due to unsupported fd tunnels";
        }
        EXPECT_FALSE(res) << "Tunnel::fromFd succesfully initialized with invalid fd " << fd;
    }
}

TEST(Tunnel, AttachesProxy)
{
    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }

    libxtun::test::Logger log;

    libxtun::test::TunOpts opts;
    auto res = libxtun::Tunnel::fromOpts(opts.get());
    EXPECT_TRUE(res) << "Tunnel::fromOpts failed with " << res.error() << " error code";

    libxtun::test::MemProxy proxy(log.defaultCallbacks());

    auto &tun = res.value();
    tun->attachProxy(&proxy);
}
