#ifndef XTUN_H
#define XTUN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum libxtun_error {
    LIBXTUN_OK = 0,
    LIBXTUN_ERR_INVALID_ARGS = -1,
    LIBXTUN_ERR_UNSUPPORTED = -2,
    /* The tun backend could not be loaded or is not present. */
    LIBXTUN_ERR_DRIVER_UNAVAILABLE = -3,
    /* The backend is present but refused to create the device. */
    LIBXTUN_ERR_DEVICE_CREATE = -4,
    /* An ancillary system call failed. */
    LIBXTUN_ERR_SYSTEM = -5,

    LIBXTUN_ERR_RESERVED_0 = -10000,
    LIBXTUN_ERR_RESERVED_1 = -10001,
    LIBXTUN_ERR_RESERVED_2 = -10002,
    LIBXTUN_ERR_RESERVED_3 = -10003,
    LIBXTUN_ERR_RESERVED_4 = -10004,
    LIBXTUN_ERR_RESERVED_5 = -10005,
    LIBXTUN_ERR_RESERVED_6 = -10006,
    LIBXTUN_ERR_RESERVED_7 = -10007,
    LIBXTUN_ERR_RESERVED_8 = -10008,
    LIBXTUN_ERR_RESERVED_9 = -10009,
};

enum libxtun_proxy_proto {
    LIBXTUN_PROXY_PROTO_AWG = 1,
    LIBXTUN_PROXY_PROTO_VLESS = 2,
    LIBXTUN_PROXY_PROTO_LAST = LIBXTUN_PROXY_PROTO_VLESS,
};

enum libxtun_status {
    LIBXTUN_STATUS_DISCONNECTED = 1,
    LIBXTUN_STATUS_CONNECTED = 2,
    /* The host itself is offline; the tunnel is not at fault. */
    LIBXTUN_STATUS_NO_NETWORK = 3,
};

struct libxtun_proxy
{
    void *handle;

    void (*onsockspawn)(int fd, void *priv);
    void *onsockspawn_priv;

    void (*loghandler)(const char *str, void *priv);
    void *loghandler_priv;

    void (*statushandler)(int status, void *priv);
    void *statushandler_priv;
};

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf);
void libxtun_proxy_free(struct libxtun_proxy *proxy);

struct libxtun_tunnel
{
    void *handle;
};

enum libxtun_killswitch_mode {
    LIBXTUN_KILLSWITCH_MODE_DISABLED = 0,
    LIBXTUN_KILLSWITCH_MODE_SOFT = 1,
    LIBXTUN_KILLSWITCH_MODE_HARD = 2,
    LIBXTUN_KILLSWITCH_MODE_LAST = LIBXTUN_KILLSWITCH_MODE_HARD,
};

struct libxtun_tunnel_opts
{
    size_t size;
    const char *const *dns;
    const char *const *dns_exceptions;
    enum libxtun_killswitch_mode killswitch_mode;
    const char *const *if_addrs;
    int mtu;
    int health_seconds;
};

int libxtun_tunnel_new(struct libxtun_tunnel *tun, const struct libxtun_tunnel_opts *opts);
int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, int fd);
int libxtun_tunnel_new_from_name(struct libxtun_tunnel *tun, const char *name);
int libxtun_tunnel_start(struct libxtun_tunnel *tun);
void libxtun_tunnel_free(struct libxtun_tunnel *tun);
int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy);

#ifdef __cplusplus
}
#endif

#endif // XTUN_H
