#include "tunnel.h"

namespace {

std::vector<std::string> parseStrList(const libxtun_str_list &l) {
    std::vector<std::string> out;
    if (l.list == nullptr) {
        return out;
    }
    out.reserve(l.size);
    const char *p = l.list;
    for (size_t i = 0; i < l.size; ++i) {
        out.emplace_back(p);
        p += out.back().size() + 1;
    }
    return out;
}

}

namespace libxtun {

Tunnel::Tunnel(const libxtun_tunnel_opts &opts)
    : m_dns(parseStrList(opts.dns)),
      m_dnsExceptions(parseStrList(opts.dns_exceptions)),
      m_killswitchMode(opts.killswitch_mode) {}

Tunnel::~Tunnel() = default;

}

int libxtun_tunnel_new(struct libxtun_tunnel *tun, struct libxtun_tunnel_opts *opts) {
    if (tun == nullptr || opts == nullptr) {
        return -1;
    }

    tun->handle = nullptr;

    if (opts->size < sizeof(*opts)) {
        return -1;
    }

    if (opts->killswitch_mode < LIBXTUN_KILLSWITCH_MODE_DISABLED ||
        opts->killswitch_mode > LIBXTUN_KILLSWITCH_MODE_LAST) {
        return -1;
    }

    tun->handle = new libxtun::Tunnel(*opts);
    return 0;
}

void libxtun_tunnel_free(struct libxtun_tunnel *tun) {
    if (tun == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Tunnel*>(tun->handle);
    tun->handle = nullptr;
}

