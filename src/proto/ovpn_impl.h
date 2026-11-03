#ifndef OVPN_IMPL_H
#define OVPN_IMPL_H

#include "ovpn.h"

#include <client/ovpncli.hpp>
#include <openvpn/io/io.hpp>

// Use the same thread-local log receiver as ovpncli.cpp in every adapter source file.
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::LogReceiver
#define OPENVPN_LOG_INFO  openvpn::ClientAPI::LogInfo
#include <openvpn/log/logthread.hpp>

#include <openvpn/common/stop.hpp>
#include <openvpn/tun/extern/config.hpp>

#include <algorithm>
#include <atomic>
#include <initializer_list>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>

namespace libxtun::proto
{
    namespace ovpn
    {
        inline bool isOneOf(std::string_view value, std::initializer_list<std::string_view> values)
        {
            return std::find(values.begin(), values.end(), value) != values.end();
        }

        [[noreturn]] inline void unsupported(const std::string &feature)
        {
            throw std::domain_error("openvpn: unsupported feature: " + feature);
        }

        ProxyProfile parseLocalProfile(const std::string &content);
        void validateSessionOptions(const openvpn::OptionList &opt);
        ProxyProfile makeLocalProfile(const openvpn::OptionList &opt);
        void validateRoutes(const ProxyProfile &profile, const openvpn::IP::Addr &server);
        int configureSession(const openvpn::OptionList &opt, const openvpn::ExternalTun::Config &conf,
                             const openvpn::IP::Addr &server, int initialMtu, openvpn::TunProp::State &state);
    }

    // Owns the OpenVPN3 client, connection threads, and local route profile.
    // Keeps OpenVPN3 details out of Ovpn's interface and stops its threads before deleting their objects.
    class Ovpn::Impl
    {
    public:
        class OvpnClient;
        class OvpnTunFactory;
        class OvpnTunClient;

        explicit Impl(Ovpn &owner);
        ~Impl();

        libxtun_error configure(const std::string &configContent);
        void attachIo(TunnelIo *io);
        void event(ProxyEvent ev);
        ProxyProfile profile() const;

    private:
        openvpn::TunClientFactory *newTunFactory(const openvpn::ExternalTun::Config &conf);
        void run() noexcept;
        void requestStop();
        void stopAndJoin();
        libxtun_error applyProfile(ProxyProfile snapshot);
        bool profileAccepted() const;
        void log(const std::string &message) noexcept;
        void status(libxtun_status value) noexcept;

        // Ovpn object used to access Tunnel I/O and the user's callbacks.
        Ovpn &m_proxy;
        // Tells OpenVPN3 to stop, even if stop was requested before connect() began.
        openvpn::Stop m_asyncStop;
        // True once stopping begins; this connection cannot be started again.
        // Atomic due to the controlling, worker, and reader threads use it without one shared mutex.
        std::atomic<bool> m_stopping { false };

        // Protects m_attached, m_started, and starting/joining m_workerThread in attachIo()/event().
        // The worker must not lock it: the controlling thread may hold it while waiting for the worker.
        std::mutex m_controlMutex;
        // True after Tunnel I/O is attached; cleared when it is detached.
        bool m_attached = false;
        // Records that the first connection attempt has begun, so later Up events cannot start another.
        bool m_started = false;

        // Runs the blocking OpenVPN3 connect() call outside the controlling thread.
        // The same thread handles sockets, timers, and packet encryption/decryption.
        std::thread m_workerThread;
        // Reads IP packets from Tunnel and queues them for the worker thread to send through OpenVPN3.
        // Stopped and joined before the OpenVPN3 objects it uses are deleted.
        std::thread m_readerThread;

        // Parsed from the local config before starting the worker; never replaced by server routes or DNS.
        ProxyProfile m_localProfile;
        // Maximum packet size for this session; also checked when the existing TUN MTU changes.
        std::atomic<int> m_sessionMtu { 0 };

        // Protects m_acceptedProfile while threads read or update it.
        // Unlock it before publishProfile(), which calls Tunnel code in the same thread.
        mutable std::mutex m_profileMutex;
        // Local routes and DNS metadata accepted by Tunnel; empty before acceptance and after requestStop().
        std::optional<ProxyProfile> m_acceptedProfile;

        // Protects m_lastStatus and prevents CONNECTED status from being sent after m_stopping becomes true.
        // Separate from m_controlMutex because the controlling thread may be waiting for the worker.
        std::mutex m_statusMutex;
        // Last status sent to the user; used to skip repeated notifications.
        std::optional<libxtun_status> m_lastStatus;

        // OpenVPN3 client for this connection.
        // Deleted after the reader thread stops, while m_asyncStop and m_proxy are still available.
        std::unique_ptr<OvpnClient> m_client;
    };
}

#endif // OVPN_IMPL_H
