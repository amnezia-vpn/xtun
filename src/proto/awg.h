#include "../proxy.h"

#include <string>

#ifndef AWG_H
#define AWG_H

namespace libxtun {
namespace proto {

class Awg : public Proxy {
  public:
    Awg(const std::string &conf);
    ~Awg();

    const char * name() override {
        return "awg";
    }
};


}
}

#endif // AWG_H
