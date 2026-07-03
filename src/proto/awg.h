#include "../proxy.h"

#include <string>

#ifndef AWG_H
#define AWG_H

namespace libxtun {
namespace proto {

enum class AwgVersion {
    VERSION_1 = 1,
    VERSION_1_5 = 2,
    VERSION_2 = 3,
    VERSION_LAST = VERSION_2,
};

class Awg : public Proxy {
  public:
    Awg(const std::string &conf);
    ~Awg();

    const char * name() override {
        switch (this->_version) {
            case AwgVersion::VERSION_1: 
                return "AmneziaWG";
            case AwgVersion::VERSION_1_5:
                return "AmneziaWG (version 1.5)";
            case AwgVersion::VERSION_2:
                return "AmneziaWG (version 2.0)";
        }
    }

  private:
    enum AwgVersion _version = AwgVersion::VERSION_1;
};


}
}

#endif // AWG_H
