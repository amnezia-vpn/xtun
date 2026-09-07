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
        class Awg final : public Proxy, private NonCopyable
        {
        public:
            static ResultXtun<std::unique_ptr<Awg>> create(const std::string &str, ClientCallbacks callbacks);
            ~Awg();

            void event(ProxyEvent ev) override;
            ProxyProfile profile() const override;

            const char *name() override
            {
                return "awg";
            }

        private:
            Awg(ClientCallbacks callbacks, awg::Config conf);

            awg::Config m_conf;
            void *m_handle = nullptr;
        };
    }
}

#endif // AWG_H
