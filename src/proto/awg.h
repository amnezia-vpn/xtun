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

    int start(const ProxyIo &io) override;
    void event(ProxyEvent ev) override;
    void stop() override;

  private:
    std::string m_conf;
    std::string m_name;
    ProxyIo m_io;
    void *m_ctx = nullptr;
};


}
}

#endif // AWG_H
