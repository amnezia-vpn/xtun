#ifndef TEST_MEMSERVER_H
#define TEST_MEMSERVER_H

#include "../util/log.h"
#include "memtun.h"
#include "proxy.h"
#include "xtun.h"

#include <sstream>
#include <stdexcept>

namespace libxtun::test
{
    class MemServer
    {
    public:
        MemServer(std::string prefix, libxtun_proxy_proto proto, const char *conf) : m_log(prefix)
        {
            auto res = libxtun::Proxy::create(proto, conf, m_log.defaultCallbacks());
            if (!res) {
                std::ostringstream ss;
                ss << "Proxy::create of server config failed with " << res.error() << " return code";
                throw std::runtime_error(ss.str());
            }
            m_proxy = std::move(res).value();
            m_proxy->attachIo(&m_tun);
            m_proxy->event(libxtun::ProxyEvent::Up);
        }

        MemTun &tun()
        {
            return m_tun;
        }

    private:
        Logger m_log;
        MemTun m_tun;
        std::unique_ptr<libxtun::Proxy> m_proxy;
    };
}

#endif
