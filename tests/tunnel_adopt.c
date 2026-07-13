#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xtun.h"

#if defined(__linux__)
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#elif defined(__APPLE__)
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#include <net/if_utun.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

static const char *error_str(int rc) {
    switch (rc) {
    case LIBXTUN_ERR_INVALID_ARGS:
        return "invalid arguments";
    case LIBXTUN_ERR_DRIVER_UNAVAILABLE:
        return "tun driver unavailable";
    case LIBXTUN_ERR_DEVICE_CREATE:
        return "not a usable tun device (needs root / wrong flags?)";
    case LIBXTUN_ERR_SYSTEM:
        return "a system call failed";
    default:
        return "unknown error";
    }
}

static void wait_enter(const char *what) {
#if defined(_WIN32)
    printf("%s is up. inspect with: netsh interface show interface\n", what);
#elif defined(__APPLE__)
    printf("%s is up. inspect with: ifconfig\n", what);
#else
    printf("%s is up. inspect with: ip link show\n", what);
#endif
    printf("press ENTER to bring it down...\n");
    getchar();
}

#if defined(__linux__)

static int create_tun(void) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    printf("created device %s (fd %d)\n", ifr.ifr_name, fd);
    return fd;
}

static int create_persistent_tun(char *name, size_t len) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0 || ioctl(fd, TUNSETPERSIST, 1) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    snprintf(name, len, "%s", ifr.ifr_name);
    printf("created persistent device %s\n", name);
    return 0;
}

static void remove_persistent_tun(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) == 0 && ioctl(fd, TUNSETPERSIST, 0) == 0) {
        printf("removed persistent device %s\n", name);
    }
    close(fd);
}

#elif defined(__APPLE__)

static int create_tun(void) {
    int fd = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return -1;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = info.ctl_id;
    sc.sc_unit = 0;
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        close(fd);
        return -1;
    }

    printf("created utun device (fd %d)\n", fd);
    return fd;
}

#elif defined(_WIN32)

typedef void *(WINAPI *WINTUN_CREATE_FN)(const WCHAR *name, const WCHAR *type, const GUID *guid);
typedef void (WINAPI *WINTUN_CLOSE_FN)(void *adapter);

#endif

static int test_adopt_fd(void) {
#if defined(_WIN32)
    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_tunfile(&tun, 0);
    if (rc == LIBXTUN_ERR_DRIVER_UNAVAILABLE) {
        printf("ok: fd adoption is unsupported on Windows (%s)\n", error_str(rc));
        return 0;
    }
    fprintf(stderr, "unexpected fd adoption result on Windows: %d (%s)\n", rc, error_str(rc));
    return 1;
#else
    int fd = create_tun();
    if (fd < 0) {
        fprintf(stderr, "failed to create a tun device (needs root?)\n");
        return 1;
    }

    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_tunfile(&tun, fd);
    if (rc != LIBXTUN_OK) {
        fprintf(stderr, "libxtun_tunnel_new_from_tunfile failed: %d (%s)\n", rc, error_str(rc));
        close(fd);
        return 1;
    }

    close(fd);
    printf("adopted; original fd closed, the tunnel runs on the library's duplicate.\n");
    wait_enter("fd-adopted tunnel");

    libxtun_tunnel_free(&tun);
    printf("tunnel down.\n");
    return 0;
#endif
}

static int test_adopt_name(void) {
#if defined(__linux__)
    char name[IFNAMSIZ];
    if (create_persistent_tun(name, sizeof(name)) < 0) {
        fprintf(stderr, "failed to create a persistent tun device (needs root?)\n");
        return 1;
    }

    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_name(&tun, name);
    if (rc != LIBXTUN_OK) {
        fprintf(stderr, "libxtun_tunnel_new_from_name failed: %d (%s)\n", rc, error_str(rc));
        remove_persistent_tun(name);
        return 1;
    }

    printf("adopted device %s by name.\n", name);
    wait_enter("name-adopted tunnel");

    libxtun_tunnel_free(&tun);
    remove_persistent_tun(name);
    printf("tunnel down.\n");
    return 0;
#elif defined(__APPLE__)
    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_name(&tun, "utun0");
    if (rc == LIBXTUN_ERR_DRIVER_UNAVAILABLE) {
        printf("ok: name adoption is unsupported on macOS (%s)\n", error_str(rc));
        return 0;
    }
    fprintf(stderr, "unexpected name adoption result on macOS: %d (%s)\n", rc, error_str(rc));
    return 1;
#elif defined(_WIN32)
    HMODULE wintun = LoadLibraryExW(L"wintun.dll", NULL,
                                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (wintun == NULL) {
        fprintf(stderr, "wintun.dll not found\n");
        return 1;
    }

    WINTUN_CREATE_FN create_adapter = (WINTUN_CREATE_FN)GetProcAddress(wintun, "WintunCreateAdapter");
    WINTUN_CLOSE_FN close_adapter = (WINTUN_CLOSE_FN)GetProcAddress(wintun, "WintunCloseAdapter");
    if (create_adapter == NULL || close_adapter == NULL) {
        fprintf(stderr, "wintun.dll is missing required functions\n");
        FreeLibrary(wintun);
        return 1;
    }

    void *adapter = create_adapter(L"xtunadopt", L"WireGuard", NULL);
    if (adapter == NULL) {
        fprintf(stderr, "failed to create an adapter (needs Administrator?)\n");
        FreeLibrary(wintun);
        return 1;
    }
    printf("created adapter xtunadopt\n");

    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_name(&tun, "xtunadopt");
    if (rc != LIBXTUN_OK) {
        fprintf(stderr, "libxtun_tunnel_new_from_name failed: %d (%s)\n", rc, error_str(rc));
        close_adapter(adapter);
        FreeLibrary(wintun);
        return 1;
    }

    printf("adopted adapter xtunadopt by name.\n");
    wait_enter("name-adopted tunnel");

    libxtun_tunnel_free(&tun);
    close_adapter(adapter);
    FreeLibrary(wintun);
    printf("tunnel down.\n");
    return 0;
#endif
}

int main(int argc, char **argv) {
    if (argc > 1) {
#if defined(_WIN32)
        (void)argv;
        fprintf(stderr, "fd adoption is not supported on Windows\n");
        return 1;
#else
        int fd = atoi(argv[1]);
        printf("adopting inherited fd %d\n", fd);

        struct libxtun_tunnel tun;
        int rc = libxtun_tunnel_new_from_tunfile(&tun, fd);
        if (rc != LIBXTUN_OK) {
            fprintf(stderr, "libxtun_tunnel_new_from_tunfile failed: %d (%s)\n", rc, error_str(rc));
            return 1;
        }

        close(fd);
        wait_enter("fd-adopted tunnel");

        libxtun_tunnel_free(&tun);
        printf("tunnel down.\n");
        return 0;
#endif
    }

    int failed = 0;
    failed |= test_adopt_fd();
    failed |= test_adopt_name();
    return failed;
}
