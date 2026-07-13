#include <stdio.h>
#include <stdlib.h>

#include "xtun.h"

#if defined(__linux__)
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#elif defined(__APPLE__)
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#include <net/if_utun.h>
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

#endif

int main(int argc, char **argv) {
#if defined(_WIN32)
    (void)argc;
    (void)argv;

    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_tunfile(&tun, 0);
    if (rc == LIBXTUN_ERR_DRIVER_UNAVAILABLE) {
        printf("ok: adoption is unsupported on Windows (%s)\n", error_str(rc));
        return 0;
    }
    fprintf(stderr, "unexpected result on Windows: %d (%s)\n", rc, error_str(rc));
    return 1;
#else
    int fd;
    if (argc > 1) {
        fd = atoi(argv[1]);
        printf("adopting inherited fd %d\n", fd);
    } else {
        fd = create_tun();
        if (fd < 0) {
            fprintf(stderr, "failed to create a tun device (needs root?)\n");
            return 1;
        }
    }

    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new_from_tunfile(&tun, fd);
    if (rc != LIBXTUN_OK) {
        fprintf(stderr, "libxtun_tunnel_new_from_tunfile failed: %d (%s)\n", rc, error_str(rc));
        return 1;
    }

    close(fd);
    printf("adopted; original fd closed, the tunnel runs on the library's duplicate.\n");

    printf("inspect it with:\n");
#if defined(__APPLE__)
    printf("  ifconfig\n");
#else
    printf("  ip link show\n");
#endif
    printf("press ENTER to bring it down...\n");
    getchar();

    libxtun_tunnel_free(&tun);
    printf("tunnel down.\n");
    return 0;
#endif
}
