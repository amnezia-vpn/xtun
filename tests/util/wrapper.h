#ifndef TEST_WRAPPER_H
#define TEST_WRAPPER_H

#include "proxy.h"
#include "xtun.h"

namespace libxtun::test
{
    class ProxyWrapper
    {
    public:
        virtual ClientCallbacks &wrapCallbacks(ClientCallbacks &callbacks) = 0;
        virtual ClientCallbacks defaultCallbacks() = 0;
        virtual libxtun_proxy &wrapProxy(libxtun_proxy &proxy) = 0;
        virtual libxtun_proxy defaultProxy() = 0;
    };

    class DummyWrapper : public ProxyWrapper
    {
    public:
        ClientCallbacks &wrapCallbacks(ClientCallbacks &callbacks) override
        {
            return callbacks;
        }
        ClientCallbacks defaultCallbacks() override
        {
            return ClientCallbacks {};
        }
        libxtun_proxy &wrapProxy(libxtun_proxy &proxy) override
        {
            return proxy;
        }
        libxtun_proxy defaultProxy() override
        {
            return libxtun_proxy {};
        }
    };
}

#endif
