#ifndef AWG_H
#define AWG_H

#include "../proxy.h"

#include "awg_conf.h"
#include "util/noncopyable.h"
#include "util/result.h"

#include <memory>
#include <string>

namespace libxtun
{
    namespace proto
    {

        class Awg : public Proxy, private NonCopyable
        {
        public:
            static ResultXtun<std::unique_ptr<Awg>> create(const std::string &str);
            Awg(awg::Config conf);
            ~Awg();

            const char *name() override
            {
                return "awg";
            }

            int start(TunnelIo &io) override;
            void event(ProxyEvent ev) override;
            void stop() override;
            ProxyProfile profile() const override;

        private:
            static void sockCb(int fd, void *priv);
            static void forwardLog(char *str, void *priv);

            awg::Config m_conf;
            TunnelIo *m_io = nullptr;
            void *m_ctx = nullptr;
        };

    }
}

#endif // AWG_H
