#include "xtun.h"

#include <gtest/gtest.h>

#include <cstring>

#if defined(__linux__) || defined(__APPLE__)
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#if defined(__linux__)
    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <linux/sockios.h>
#elif defined(__APPLE__)
    #include <net/if.h>
    #include <net/if_utun.h>
    #include <sys/kern_control.h>
    #include <sys/sys_domain.h>
#elif defined(_WIN32)
    #include <windows.h>
#endif

namespace
{

    bool privileged()
    {
#if defined(_WIN32)
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (::AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0,
                                       0, 0, 0, &adminGroup)) {
            ::CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            ::FreeSid(adminGroup);
        }
        return isAdmin != FALSE;
#else
        return ::geteuid() == 0;
#endif
    }

    libxtun_tunnel_opts default_opts()
    {
        libxtun_tunnel_opts opts {};
        opts.size = sizeof(opts);
        opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        return opts;
    }

#if defined(__linux__)

    // Independent of libxtun: ask the kernel directly whether the interface exists.
    bool iface_exists(const char *name)
    {
        int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock < 0) {
            return false;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        bool exists = ::ioctl(sock, SIOCGIFINDEX, &ifr) == 0;
        ::close(sock);
        return exists;
    }

    int create_tun(char *name, size_t len)
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            ::close(fd);
            return -1;
        }
        std::snprintf(name, len, "%s", ifr.ifr_name);
        return fd;
    }

    int create_persistent_tun(char *name, size_t len)
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (::ioctl(fd, TUNSETIFF, &ifr) < 0 || ::ioctl(fd, TUNSETPERSIST, 1) < 0) {
            ::close(fd);
            return -1;
        }
        ::close(fd);
        std::snprintf(name, len, "%s", ifr.ifr_name);
        return 0;
    }

    void remove_persistent_tun(const char *name)
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        if (::ioctl(fd, TUNSETIFF, &ifr) == 0) {
            ::ioctl(fd, TUNSETPERSIST, 0);
        }
        ::close(fd);
    }

#elif defined(__APPLE__)

    int create_tun(char *name, size_t len)
    {
        int fd = ::socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            return -1;
        }
        struct ctl_info info;
        std::memset(&info, 0, sizeof(info));
        std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
        if (::ioctl(fd, CTLIOCGINFO, &info) < 0) {
            ::close(fd);
            return -1;
        }
        struct sockaddr_ctl sc;
        std::memset(&sc, 0, sizeof(sc));
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_id = info.ctl_id;
        sc.sc_unit = 0;
        if (::connect(fd, reinterpret_cast<struct sockaddr *>(&sc), sizeof(sc)) < 0) {
            ::close(fd);
            return -1;
        }
        socklen_t ifnameLen = static_cast<socklen_t>(len);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &ifnameLen) < 0) {
            ::close(fd);
            return -1;
        }
        return fd;
    }

#endif

} // namespace

TEST(TunnelLifecycle, BringUpAndDown)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }
    libxtun_tunnel_opts opts = default_opts();
    libxtun_tunnel tun;
    int rc = libxtun_tunnel_new(&tun, &opts);
    ASSERT_EQ(rc, LIBXTUN_OK);
#if defined(__linux__)
    EXPECT_TRUE(iface_exists("xtun")) << "tunnel reported success but the xtun interface is absent";
#endif
    libxtun_tunnel_free(&tun);
#if defined(__linux__)
    EXPECT_FALSE(iface_exists("xtun")) << "the xtun interface outlived the tunnel";
#endif
}

#if defined(__linux__) || defined(__APPLE__)

TEST(TunnelLifecycle, AdoptByFd)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root";
    }
    char name[IFNAMSIZ] = { 0 };
    int fd = create_tun(name, sizeof(name));
    ASSERT_GE(fd, 0) << "could not create a tun device";

    libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_tunfile(&tun, fd);
    ::close(fd);
    ASSERT_EQ(rc, LIBXTUN_OK);
    #if defined(__linux__)
    EXPECT_TRUE(iface_exists(name)) << "adopted interface " << name << " vanished after we closed our fd";
    #endif
    libxtun_tunnel_free(&tun);
    #if defined(__linux__)
    EXPECT_FALSE(iface_exists(name)) << "adopted interface " << name << " outlived the tunnel";
    #endif
}

#endif

#if defined(__linux__)

TEST(TunnelLifecycle, AdoptByName)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: creating a persistent tun device requires root";
    }
    char name[IFNAMSIZ];
    ASSERT_EQ(create_persistent_tun(name, sizeof(name)), 0) << "could not create a persistent tun device";

    libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_name(&tun, name);
    if (rc != LIBXTUN_OK) {
        remove_persistent_tun(name);
        FAIL() << "libxtun_tunnel_new_from_name failed: " << rc;
    }
    EXPECT_TRUE(iface_exists(name)) << "adopted interface " << name << " is absent";
    libxtun_tunnel_free(&tun);
    EXPECT_TRUE(iface_exists(name)) << "freeing the tunnel destroyed the persistent interface " << name;
    remove_persistent_tun(name);
    EXPECT_FALSE(iface_exists(name)) << "interface " << name << " lingered after removal";
}

#elif defined(_WIN32)

TEST(TunnelLifecycle, AdoptByName)
{
    if (!privileged()) {
        GTEST_SKIP() << "skipped: creating a wintun adapter requires Administrator";
    }
    typedef void *(WINAPI * create_fn)(const WCHAR *, const WCHAR *, const GUID *);
    typedef void(WINAPI * close_fn)(void *);

    HMODULE wintun =
            LoadLibraryExW(L"wintun.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    ASSERT_NE(wintun, nullptr) << "wintun.dll not found";
    auto create_adapter = reinterpret_cast<create_fn>(GetProcAddress(wintun, "WintunCreateAdapter"));
    auto close_adapter = reinterpret_cast<close_fn>(GetProcAddress(wintun, "WintunCloseAdapter"));
    if (create_adapter == nullptr || close_adapter == nullptr) {
        FreeLibrary(wintun);
        FAIL() << "wintun.dll is missing required entry points";
    }

    void *adapter = create_adapter(L"xtunadopt", L"WireGuard", nullptr);
    if (adapter == nullptr) {
        FreeLibrary(wintun);
        FAIL() << "creating an adapter requires Administrator";
    }

    libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_name(&tun, "xtunadopt");
    if (rc != LIBXTUN_OK) {
        close_adapter(adapter);
        FreeLibrary(wintun);
        FAIL() << "libxtun_tunnel_new_from_name failed: " << rc;
    }
    libxtun_tunnel_free(&tun);
    close_adapter(adapter);
    FreeLibrary(wintun);
}

#endif
