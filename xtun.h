#include <stddef.h>

#ifndef XTUN_H
#define XTUN_H

#ifdef __cplusplus
extern "C" {
#endif

enum libxtun_status {
    LIBXTUN_STATUS_DISCONNECTED = 1,
    LIBXTUN_STATUS_CONNECTED = 2,
};

enum libxtun_error {
    LIBXTUN_OK = 0,
    LIBXTUN_ERR_INVALID_ARGS = -1,
    /* The tun backend could not be loaded or is not present. */
    LIBXTUN_ERR_DRIVER_UNAVAILABLE = -2,
    /* The backend is present but refused to create the device. */
    LIBXTUN_ERR_DEVICE_CREATE = -3,
    /* An ancillary system call failed. */
    LIBXTUN_ERR_SYSTEM = -4,
};

enum libxtun_proxy_proto {
    LIBXTUN_PROXY_PROTO_AWG = 1,
    LIBXTUN_PROXY_PROTO_VLESS = 2,
    LIBXTUN_PROXY_PROTO_LAST = LIBXTUN_PROXY_PROTO_VLESS,
};

struct libxtun_proxy {
    void *handle;
    void(*onsockspawn)(int fd, void *priv);
    void *onsockspawn_priv;
    void(*loghandler)(const char *str, void *priv);
    void *loghandler_priv;

    /* 
    * status handler could return:
    * - libxtun_status, in case of normal behavior
    * - libxtun_error,  in case of runtime error
    */
    void(*statushandler)(int status, void *priv);
    void *statushandler_priv;
};

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf);
void libxtun_proxy_free(struct libxtun_proxy *proxy);

/* `list` points to `size` consecutive NUL-terminated strings. */
struct libxtun_str_list {
    const char *list;
    size_t size;
};

struct libxtun_tunnel {
    void *handle;
};

enum libxtun_killswitch_mode {
    LIBXTUN_KILLSWITCH_MODE_DISABLED = 0,
    LIBXTUN_KILLSWITCH_MODE_SOFT = 1,
    LIBXTUN_KILLSWITCH_MODE_HARD = 2,
    LIBXTUN_KILLSWITCH_MODE_LAST = LIBXTUN_KILLSWITCH_MODE_HARD,
};

struct libxtun_tunnel_opts {
    size_t size;
    struct libxtun_str_list dns;
    struct libxtun_str_list dns_exceptions;
    enum libxtun_killswitch_mode killswitch_mode;
    struct libxtun_str_list if_addrs;
    int mtu;
};

int libxtun_tunnel_new(struct libxtun_tunnel *tun, struct libxtun_tunnel_opts *opts);
int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, int fd);
int libxtun_tunnel_new_from_name(struct libxtun_tunnel *tun, const char *name);
int libxtun_tunnel_start(struct libxtun_tunnel *tun);
void libxtun_tunnel_free(struct libxtun_tunnel *tun);

/* Returns LIBXTUN_OK once the proxy is running against the tunnel, or a
 * negative libxtun_error if it could not be started. */
int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy);

#ifdef __cplusplus
}
#endif

#endif // XTUN_H
