#include "ovpn_impl.h"

#include <utility>

namespace libxtun::proto
{
    void Ovpn::Impl::attachIo(TunnelIo *io)
    {
        std::lock_guard<std::mutex> lock(m_controlMutex);
        if (io == nullptr) {
            m_attached = false;
            // Tunnel has already removed this proxy's profile listener.
            // Stop the connection and wait for its threads before detaching Tunnel I/O.
            stopAndJoin();
            m_proxy.Proxy::attachIo(nullptr);
            return;
        }
        if (m_stopping.load() || m_attached) {
            log("openvpn: create a new Proxy provider before attaching I/O again");
            return;
        }
        m_proxy.Proxy::attachIo(io);
        m_attached = true;
    }

    void Ovpn::Impl::event(ProxyEvent ev)
    {
        std::unique_lock<std::mutex> lock(m_controlMutex);
        switch (ev) {
        case ProxyEvent::Up:
            if (!m_attached || m_started || m_stopping.load()) {
                return;
            }
            m_started = true;
            try {
                m_workerThread = std::thread([this]() { run(); });
            } catch (const std::exception &e) {
                lock.unlock();
                log(e.what());
                requestStop();
                status(LIBXTUN_STATUS_DISCONNECTED);
            }
            break;
        case ProxyEvent::Down:
            // Ignore Down before the first connection attempt.
            // Calling stopAndJoin() now would permanently prevent a later Up from starting it.
            if (m_started) {
                stopAndJoin();
            }
            break;
        case ProxyEvent::MtuUpdate: {
            const int sessionMtu = m_sessionMtu.load();
            const int tunMtu = m_proxy.tunMtu();
            if (sessionMtu > 0 && (tunMtu <= 0 || tunMtu > sessionMtu)) {
                log("openvpn: existing TUN MTU is incompatible with the session; a new connection is required");
                stopAndJoin();
            }
            break;
        }
        }
    }

    void Ovpn::Impl::requestStop()
    {
        {
            std::lock_guard<std::mutex> lock(m_statusMutex);
            if (m_stopping.exchange(true)) {
                return;
            }
        }
        {
            std::lock_guard<std::mutex> lock(m_profileMutex);
            m_acceptedProfile.reset();
        }
        // Wake blocked reads, wait for active I/O calls, and reject future I/O through this proxy.
        // Tunnel keeps ownership of the device.
        m_sessionMtu.store(0);
        m_proxy.m_io.halt();
        m_asyncStop.stop();
    }

    void Ovpn::Impl::stopAndJoin()
    {
        requestStop();
        // OpenVPN3 callbacks use requestStop(); the controlling caller waits for the worker thread here.
        if (m_workerThread.joinable() && m_workerThread.get_id() != std::this_thread::get_id()) {
            m_workerThread.join();
        }
    }

    libxtun_error Ovpn::Impl::applyProfile(ProxyProfile snapshot)
    {
        {
            std::lock_guard<std::mutex> lock(m_profileMutex);
            // Do not expose a profile until Tunnel accepts it.
            m_acceptedProfile.reset();
        }
        if (m_stopping.load()) {
            return LIBXTUN_ERR_UNSUPPORTED;
        }
        // publishProfile() waits for Tunnel to apply the local routes.
        // Unlock m_profileMutex first so that call can read our profile without locking it twice.
        const auto rc = m_proxy.publishProfile(snapshot);
        if (rc == LIBXTUN_OK) {
            std::lock_guard<std::mutex> lock(m_profileMutex);
            if (m_stopping.load()) {
                return LIBXTUN_ERR_UNSUPPORTED;
            }
            // Mark the profile as accepted only after Tunnel reports success.
            m_acceptedProfile = std::move(snapshot);
        }
        return rc;
    }

    ProxyProfile Ovpn::Impl::profile() const
    {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        return m_acceptedProfile.value_or(ProxyProfile {});
    }

    bool Ovpn::Impl::profileAccepted() const
    {
        std::lock_guard<std::mutex> lock(m_profileMutex);
        return m_acceptedProfile.has_value();
    }

    // Calls the user's onLog callback directly on whichever thread called log().
    void Ovpn::Impl::log(const std::string &message) noexcept
    {
        try {
            m_proxy.emitLog(message.c_str());
        } catch (...) {
            // Ignore exceptions from onLog: a logging error must not stop the VPN or terminate a thread.
        }
    }

    void Ovpn::Impl::status(libxtun_status value) noexcept
    {
        std::lock_guard<std::mutex> lock(m_statusMutex);
        if (m_lastStatus == value || (value == LIBXTUN_STATUS_CONNECTED && m_stopping.load())) {
            return;
        }
        m_lastStatus = value;
        try {
            m_proxy.publishStatus(value);
        } catch (...) {
            log("openvpn: status callback threw an exception");
        }
    }

    Ovpn::Ovpn(ClientCallbacks callbacks) : Proxy(callbacks), m_impl(std::make_unique<Impl>(*this))
    {
    }

    Ovpn::~Ovpn() = default;

    ResultXtun<std::unique_ptr<Ovpn>> Ovpn::create(const std::string &str, ClientCallbacks callbacks)
    {
        try {
            auto ovpn = std::unique_ptr<Ovpn>(new Ovpn(callbacks));
            if (auto rc = ovpn->m_impl->configure(str); rc != LIBXTUN_OK) {
                return libxtun::fail(rc);
            }
            return ovpn;
        } catch (const std::bad_alloc &) {
            return libxtun::fail(LIBXTUN_ERR_SYSTEM);
        } catch (const std::exception &e) {
            try {
                if (callbacks.onLog != nullptr) {
                    callbacks.onLog(e.what(), callbacks.onLogPriv);
                }
            } catch (...) {
            }
            return libxtun::fail(LIBXTUN_ERR_INVALID_ARGS);
        }
    }

    void Ovpn::attachIo(TunnelIo *io)
    {
        m_impl->attachIo(io);
    }

    void Ovpn::event(ProxyEvent ev)
    {
        m_impl->event(ev);
    }

    ProxyProfile Ovpn::profile() const
    {
        return m_impl->profile();
    }
}
