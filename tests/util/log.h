#ifndef TEST_LOG_H
#define TEST_LOG_H

#include "proxy.h"

namespace libxtun::test
{
    class Logger
    {
    public:
        Logger() {};
        explicit Logger(std::string prefix) : m_prefix(prefix) {};

        ClientCallbacks defaultCallbacks()
        {
            ClientCallbacks callbacks {};
            return wrapCallbacks(callbacks);
        }

        ClientCallbacks &wrapCallbacks(ClientCallbacks &callbacks)
        {
            callbacks.onLog = Logger::clog;
            callbacks.onLogPriv = this;
            return callbacks;
        }

        static void clog(const char *message, void *priv)
        {
            reinterpret_cast<Logger *>(priv)->log(message);
        }
        void log(const char *message)
        {
            if (!m_prefix.empty()) {
                printf("[%s] %s\n", m_prefix.c_str(), message);
            } else {
                printf("%s\n", message);
            }
        }

    private:
        std::string m_prefix;
    };
}

#endif
