#ifndef VLESS_H
#define VLESS_H

#include "../proxy.h"

#include <string>

namespace libxtun
{
    namespace proto
    {

        class Vless : public Proxy
        {
        public:
            Vless(const std::string &conf);
            ~Vless();

            const char *name() override
            {
                return "vless";
            }
        };

    }
}

#endif // VLESS_H
