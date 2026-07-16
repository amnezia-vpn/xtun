#include "awgconfig.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>

#include "config.h"
#include "containers.h"
#include "ipc-uapi.h"

/* userspace_get_device() and userspace_get_wireguard_interfaces() are pulled in
   by ipc-uapi.h but never called here; only userspace_set_device() is used.
   string_list_add()'s real definition lives in ipc.c (kernel/libmnl path), and
   curve25519 is only needed to reconstruct public keys on the unused get path. */
struct string_list;
int string_list_add(struct string_list *list, const char *str);
int string_list_add(struct string_list *list, const char *str) {
    (void)list;
    (void)str;
    return -1;
}

void curve25519_generate_public(uint8_t pub[CURVE25519_KEY_SIZE],
                                const uint8_t secret[CURVE25519_KEY_SIZE]) {
    (void)pub;
    (void)secret;
}

int awg_apply_config(const char *conf, const char *name, const char **err) {
    struct config_ctx ctx;
    struct wgdevice *dev;
    const char *p;

    if (err)
        *err = NULL;
    if (!conf || !name) {
        if (err)
            *err = "invalid arguments";
        return -1;
    }
    if (!config_read_init(&ctx, false)) {
        if (err)
            *err = "out of memory";
        return -1;
    }

    for (p = conf; *p;) {
        size_t len = strcspn(p, "\n");
        char *line = malloc(len + 1);

        if (!line) {
            free_wgdevice(ctx.device);
            if (err)
                *err = "out of memory";
            return -1;
        }
        memcpy(line, p, len);
        line[len] = '\0';

        int ok = config_read_line(&ctx, line);
        free(line);
        if (!ok) {
            if (err)
                *err = "configuration parsing error";
            return -1;
        }

        p += len;
        if (*p == '\n')
            ++p;
    }

    dev = config_read_finish(&ctx);
    if (!dev) {
        if (err)
            *err = "invalid configuration";
        return -1;
    }

    strncpy(dev->name, name, IFNAMSIZ - 1);
    dev->name[IFNAMSIZ - 1] = '\0';

    int rc = userspace_set_device(dev);
    free_wgdevice(dev);

    if (rc != 0) {
        if (err)
            *err = strerror(-rc);
        return -1;
    }
    return 0;
}
