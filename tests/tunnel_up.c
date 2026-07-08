#include <stdio.h>
#include <stddef.h>

#include "xtun.h"

static const char *error_str(int rc) {
    switch (rc) {
    case LIBXTUN_ERR_INVALID_ARGS:
        return "invalid arguments";
    case LIBXTUN_ERR_DRIVER_UNAVAILABLE:
        return "tun driver unavailable (on Windows: is wintun.dll next to the exe?)";
    case LIBXTUN_ERR_DEVICE_CREATE:
        return "device creation refused (needs root / Administrator)";
    case LIBXTUN_ERR_SYSTEM:
        return "a system call failed";
    default:
        return "unknown error";
    }
}

int main(void) {
    struct libxtun_tunnel_opts opts;
    opts.size = sizeof(opts);
    opts.dns.list = NULL;
    opts.dns.size = 0;
    opts.dns_exceptions.list = NULL;
    opts.dns_exceptions.size = 0;
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;

    struct libxtun_tunnel tun;
    int rc = libxtun_tunnel_new(&tun, &opts);
    if (rc != LIBXTUN_OK) {
        fprintf(stderr, "libxtun_tunnel_new failed: %d (%s)\n", rc, error_str(rc));
        return 1;
    }

    printf("tunnel up. inspect it with:\n");
#if defined(_WIN32)
    printf("  netsh interface show interface\n");
#elif defined(__APPLE__)
    printf("  ifconfig\n");
#else
    printf("  ip link show xtun\n");
#endif
    printf("press ENTER to bring it down...\n");
    getchar();

    libxtun_tunnel_free(&tun);
    printf("tunnel down.\n");
    return 0;
}
