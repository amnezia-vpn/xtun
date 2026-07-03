#include "../proxy.h"

#include <string>

#ifndef VLESS_H
#define VLESS_H

namespace libxtun {
namespace proto {

class Vless : public Proxy {
  public:
    Vless(const std::string &conf);
    ~Vless();

    const char * name() override {
        return "vless";
    }
};


}
}

#endif // VLESS_H
