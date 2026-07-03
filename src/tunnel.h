#include "proxy.h"

#ifndef TUNNEL_H
#define TUNNEL_H

namespace libxtun {


class Tunnel {
  public:
    Tunnel();
    ~Tunnel();

    void attachProxy(Proxy &&proxy);

  private:
};


}

#endif // TUNNEL_H
