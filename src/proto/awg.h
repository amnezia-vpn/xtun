#include "../proxy.h"

#include "awg_conf.h"
#include "util/noncopyable.h"
#include "util/result.h"

#include <memory>
#include <mutex>
#include <string>

#ifndef AWG_H
#define AWG_H

namespace libxtun {
namespace proto {

class Awg : public Proxy, private NonCopyable {
  public:
    static ResultXtun<std::unique_ptr<Awg>> create(const std::string& str);
    Awg(awg::Config conf);
    ~Awg();

    const char * name() override {
        return "awg";
    }

    int start(const ProxyIo &io) override;
    void event(ProxyEvent ev) override;
    void stop() override;
    std::vector<std::string> routes() override;
    void reapplyBypass() override;

  private:
    static void sockCb(int fd, void *priv);
    void applyBypass(int fd, int family);

    awg::Config m_conf;
    ProxyIo m_io;
    void *m_ctx = nullptr;
    std::mutex m_sockMtx;
    int m_sock4 = -1;
    int m_sock6 = -1;
};

}
}

#endif // AWG_H
