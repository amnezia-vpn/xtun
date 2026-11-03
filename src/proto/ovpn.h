#ifndef OVPN_H
#define OVPN_H

#include "proxy.h"

#include <memory>
#include <string>

namespace libxtun::proto
{
    class Ovpn final : public Proxy
    {
    public:
        static ResultXtun<std::unique_ptr<Ovpn>> create(const std::string &str, ClientCallbacks callbacks);
        ~Ovpn() override;

        void attachIo(TunnelIo *io) override;
        void event(ProxyEvent ev) override;
        ProxyProfile profile() const override;

        const char *name() override
        {
            return "openvpn";
        }

    private:
        explicit Ovpn(ClientCallbacks callbacks);

        class Impl;
        std::unique_ptr<Impl> m_impl;
    };
}

#endif // OVPN_H
