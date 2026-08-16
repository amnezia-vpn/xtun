#include <xtun.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#ifndef PROXY_H
#define PROXY_H

namespace libxtun {


class Tunnel;

enum class ProxyEvent { Up, Down, MtuUpdate };

struct ProxyIo {
    std::function<int(void *buf, int len)> read;
    std::function<int(const void *buf, int len)> write;
    std::function<int()> mtu;
};

class Proxy {
  public:
    virtual ~Proxy() = 0;

    virtual const char *name() = 0;

    virtual int start(const ProxyIo &io) = 0;
    virtual void event(ProxyEvent ev) = 0;
    virtual void stop() = 0;

    virtual std::vector<std::string> routes() = 0;

    virtual void reapplyBypass() {}

    void bind(struct libxtun_proxy *cproxy) { m_cproxy = cproxy; }
    void setInterface(const std::string &ifname) { m_ifname = ifname; }
    void setBypassToken(uint32_t token) { m_bypassToken = token; }

  protected:
    void cancelIo();

    struct libxtun_proxy *m_cproxy = nullptr;
    std::string m_ifname;
    uint32_t m_bypassToken = 0;

  private:
    friend class Tunnel;

    Tunnel *m_tunnel = nullptr;
};


}

#endif // PROXY_H
