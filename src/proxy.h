#include <xtun.h>

#ifndef PROXY_H
#define PROXY_H

namespace libxtun {


class Proxy {
  public:
    virtual ~Proxy() = 0;

    virtual const char* name() = 0;
};


}

#endif // PROXY_H
