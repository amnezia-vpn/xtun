#ifndef TEST_OVPN_H
#define TEST_OVPN_H

#include "proto/ovpn.h"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <stdexcept>
#include <string>

namespace libxtun::test
{
    // Client-only test credentials; session tests use a fresh profile supplied by their local server.
    inline std::string ovpnProfile()
    {
        const auto path = std::filesystem::path(XTUN_TEST_OVPN_CLIENT_PROFILE);
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("Cannot read OpenVPN test profile: " + path.string());
        }
        return { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
    }

    // Records status callbacks and lets each test control socket and log callbacks.
    class TestOvpnEvents
    {
    public:
        std::atomic<unsigned> connections { 0 };
        std::atomic<unsigned> disconnections { 0 };
        // set_value() signals the first status; the test waits on the matching future.
        std::promise<void> connected;
        std::promise<void> disconnected;
        std::function<void(int)> onSocket;
        std::function<void(const char *)> onLog;

        ClientCallbacks callbacks()
        {
            ClientCallbacks result;
            result.onSocket = [](int fd, void *priv) {
                auto &events = *static_cast<TestOvpnEvents *>(priv);
                if (events.onSocket) {
                    events.onSocket(fd);
                }
            };
            result.onSocketPriv = this;
            result.onLog = [](const char *message, void *priv) {
                auto &events = *static_cast<TestOvpnEvents *>(priv);
                if (events.onLog) {
                    events.onLog(message);
                }
            };
            result.onLogPriv = this;
            result.onStatus = [](int status, void *priv) {
                auto &events = *static_cast<TestOvpnEvents *>(priv);
                if (status == LIBXTUN_STATUS_CONNECTED && ++events.connections == 1) {
                    events.connected.set_value();
                }
                if (status == LIBXTUN_STATUS_DISCONNECTED && ++events.disconnections == 1) {
                    events.disconnected.set_value();
                }
            };
            result.onStatusPriv = this;
            return result;
        }
    };

    // Returns the result chosen by the test when OpenVPN publishes local routes and DNS metadata.
    class TestOvpnProfileListener final : public ProxyProfileListener
    {
    public:
        std::function<libxtun_error(Proxy &, const ProxyProfile &)> onChange;

        libxtun_error onProfileChanged(Proxy &source, const ProxyProfile &snapshot) override
        {
            return onChange(source, snapshot);
        }
    };
}

#endif // TEST_OVPN_H
