#include <stddef.h>

#ifndef XTUN_H
#define XTUN_H

#ifdef __cplusplus
extern "C" {
#endif

enum libxtun_proxy_proto {
    LIBXTUN_PROXY_PROTO_AWG = 1,
    LIBXTUN_PROXY_PROTO_VLESS = 2,
    LIBXTUN_PROXY_PROTO_LAST = LIBXTUN_PROXY_PROTO_VLESS,
};

struct libxtun_proxy {
    void *handle;
    void(*onsockspawn)(int fd, void *priv);
    void(*loghandler)(const char *str, void *priv);
};

int libxtun_proxy_new(struct libxtun_proxy *proxy, enum libxtun_proxy_proto proto, const char *conf);
void libxtun_proxy_free(struct libxtun_proxy *proxy);

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
};

int libxtun_tunnel_new(struct libxtun_tunnel *tun, struct libxtun_tunnel_opts *opts);
int libxtun_tunnel_new_from_tunfile(struct libxtun_tunnel *tun, const char *path);
void libxtun_tunnel_free(struct libxtun_tunnel *tun);

void libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy);

#ifdef __cplusplus
}
#endif

#endif // XTUN_H
