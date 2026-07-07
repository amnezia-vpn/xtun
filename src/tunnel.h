#include "proxy.h"
#include "xtun.h"

#include <string>
#include <vector>

#ifndef TUNNEL_H
#define TUNNEL_H

namespace libxtun {


class Tunnel {
  public:
    Tunnel(const libxtun_tunnel_opts &opts);
    ~Tunnel();

    void attachProxy(Proxy &&proxy);

  private:
    std::vector<std::string> m_dns;
    std::vector<std::string> m_dnsExceptions;
    libxtun_killswitch_mode m_killswitchMode;
};


}

#endif // TUNNEL_H
