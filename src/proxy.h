#include <xtun.h>

#include "tunnel_io.h"

#include <string>
#include <vector>

#ifndef PROXY_H
#define PROXY_H

namespace libxtun {


class Tunnel;

enum class ProxyEvent { Up, Down, MtuUpdate };

struct ProxyProfile {
    std::vector<std::string> routes;
    std::vector<std::string> dns_servers;
    std::vector<std::string> addresses;
};

struct ClientCallbacks {
    void (*on_socket)(int fd, void *priv) = nullptr;
    void *on_socket_priv = nullptr;
    void (*on_log)(const char *message, void *priv) = nullptr;
    void *on_log_priv = nullptr;
};

class Proxy {
  public:
    virtual ~Proxy() = 0;

    virtual const char *name() = 0;

    virtual int start(TunnelIo &io) = 0;
    virtual void event(ProxyEvent ev) = 0;
    virtual void stop() = 0;

    virtual ProxyProfile profile() const = 0;

    void bind(const ClientCallbacks &callbacks) { m_callbacks = callbacks; }
    void setInterface(const std::string &ifname) { m_ifname = ifname; }

  protected:
    void cancelIo();
    void emitLog(const char *message) noexcept;
    void registerBypassSocket(int fd, int family);
    void bypassSocket(int fd, int family);

    std::string m_ifname;

  private:
    friend class Tunnel;

    ClientCallbacks m_callbacks;
    Tunnel *m_tunnel = nullptr;
};


}

#endif // PROXY_H
