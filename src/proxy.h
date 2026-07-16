#include <xtun.h>

#include <functional>

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

    void bind(struct libxtun_proxy *cproxy) { m_cproxy = cproxy; }

  protected:
    void cancelIo();

    struct libxtun_proxy *m_cproxy = nullptr;

  private:
    friend class Tunnel;

    Tunnel *m_tunnel = nullptr;
};


}

#endif // PROXY_H
