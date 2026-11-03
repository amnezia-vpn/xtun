#include "ovpn_impl.h"

#include "net/socket.h"

#include <openvpn/init/initprocess.hpp>

namespace libxtun::proto
{
    // Adapts OpenVPN3 Core's connection callbacks to Proxy logging, status, and socket protection.
    // Selects TUN factory so OpenVPN3 Core uses Tunnel's existing I/O.
    class Ovpn::Impl::OvpnClient final : public openvpn::ClientAPI::OpenVPNClient
    {
    public:
        explicit OvpnClient(Impl &impl) : m_impl(impl)
        {
        }

        openvpn::TunClientFactory *new_tun_factory(const openvpn::ExternalTun::Config &conf,
                                                   const openvpn::OptionList &) override
        {
            return m_impl.newTunFactory(conf);
        }

        bool socket_protect(openvpn_io::detail::socket_type socket, std::string, bool ipv6) override
        {
            if (m_impl.m_stopping.load()) {
                return false;
            }
            try {
                if (!ipv6) {
                    const auto rc = m_impl.m_proxy.sockCb(net::toAbiDescriptor(socket));
                    if (rc == LIBXTUN_OK && !m_impl.m_stopping.load()) {
                        return true;
                    }
                    m_impl.log("openvpn: socket protection failed: " + std::to_string(rc));
                } else {
                    m_impl.log("openvpn: IPv6 transport is not supported");
                }
            } catch (...) {
                m_impl.log("openvpn: socket protection callback failed");
            }
            m_impl.requestStop();
            return false;
        }

        bool pause_on_connection_timeout() override
        {
            return false;
        }

        void event(const openvpn::ClientAPI::Event &ev) override
        {
            m_impl.log("openvpn: " + ev.name + (ev.info.empty() ? "" : ": " + ev.info));
            if (ev.name == "CONNECTED") {
                if (!m_impl.m_stopping.load() && m_impl.profileAccepted()) {
                    m_impl.status(LIBXTUN_STATUS_CONNECTED);
                } else if (!m_impl.m_stopping.load()) {
                    m_impl.log("openvpn: CONNECTED before local routes were accepted");
                    m_impl.requestStop();
                }
                return;
            }
            if (ovpn::isOneOf(ev.name, { "RECONNECTING", "PAUSE", "RESUME", "RELAY" })) {
                m_impl.log("openvpn: " + ev.name + " is not supported; stopping the connection");
                m_impl.requestStop();
                return;
            }
            const bool interactiveAuthInfo = ev.name == "INFO"
                    && (ev.info.find("WEB_AUTH:") != std::string::npos || ev.info.find("CR_TEXT:") != std::string::npos);
            if (ev.name == "AUTH_PENDING" || interactiveAuthInfo) {
                m_impl.log("openvpn: interactive authentication is not supported");
                m_impl.requestStop();
                return;
            }
            if (ev.error || ev.fatal
                || ovpn::isOneOf(ev.name, { "DISCONNECTED", "UNSUPPORTED_FEATURE", "COMPRESSION_ENABLED" })) {
                m_impl.requestStop();
            }
        }

        void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &ev) override
        {
            m_impl.log("openvpn: app control protocol: " + ev.protocol);
            if (ev.protocol != "internal:supported_protocols") {
                m_impl.log("openvpn: application control channel requests are not supported");
                m_impl.requestStop();
            }
        }

        void log(const openvpn::ClientAPI::LogInfo &info) override
        {
            m_impl.log(info.text);
        }

        void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &request) override
        {
            request.error = true;
            request.errorText = "openvpn: External PKI is not supported";
            m_impl.log(request.errorText);
            m_impl.requestStop();
        }

        void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &request) override
        {
            request.error = true;
            request.errorText = "openvpn: External PKI is not supported";
            m_impl.log(request.errorText);
            m_impl.requestStop();
        }

    protected:
        openvpn::Stop *get_async_stop() override
        {
            return &m_impl.m_asyncStop;
        }

    private:
        Impl &m_impl;
    };

    Ovpn::Impl::Impl(Ovpn &owner) : m_proxy(owner)
    {
        // Keep OpenVPN3 initialized between proxy instances. In 3.11.7, reinitializing
        // its static BIO_METHOD replaces the pointer without freeing the previous allocation.
        static const openvpn::InitProcess::Init processInit;
        m_client = std::make_unique<OvpnClient>(*this);
    }

    Ovpn::Impl::~Impl()
    {
        stopAndJoin();
        m_client.reset();
    }

    libxtun_error Ovpn::Impl::configure(const std::string &configContent)
    {
        openvpn::ClientAPI::OpenVPNClientHelper helper;

        // ProfileMerge::FOLLOW_NONE: no external files are read.
        const auto merged = helper.merge_config_string(configContent);
        if (merged.status != "MERGE_SUCCESS") {
            log("openvpn: " + merged.errorText);
            if (merged.errorText.rfind("ERR_PROFILE_CANT_FOLLOW_LINK:", 0) == 0
                || ovpn::isOneOf(merged.status, { "MERGE_REF_FAIL", "MERGE_MULTIPLE_REF_FAIL" })) {
                return LIBXTUN_ERR_UNSUPPORTED;
            }
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        openvpn::ClientAPI::Config config;
        config.content = merged.profileContent;
        config.protoVersionOverride = 4;
        config.dco = false;
        config.tunPersist = false;
        config.compressionMode = "no";
        config.retryOnAuthFailed = false;
        config.echo = true;
        // Enable INFO events from the server in event() callback.
        // It's used to detect browser login (WEB_AUTH) and text challenges (CR_TEXT).
        config.info = true;

        const auto eval = m_client->eval_config(config);
        if (eval.error) {
            log("openvpn: " + eval.message);
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        if (!eval.autologin || eval.externalPki || eval.privateKeyPasswordRequired || !eval.staticChallenge.empty()) {
            log("openvpn: an inline client certificate and an unencrypted private key are required; "
                "username/password, External PKI and interactive authentication are not supported");
            return LIBXTUN_ERR_UNSUPPORTED;
        }

        try {
            m_localProfile = ovpn::parseLocalProfile(config.content);
        } catch (const std::domain_error &e) {
            log(e.what());
            return LIBXTUN_ERR_UNSUPPORTED;
        }
        return LIBXTUN_OK;
    }

    void Ovpn::Impl::run() noexcept
    {
        try {
            if (!m_stopping.load()) {
                // openvpn::ClientAPI::OpenVPNClient::connect() is blocking call
                const auto result = m_client->connect();
                if (result.error) {
                    log("openvpn: connect failed: " + result.status + ": " + result.message);
                    if (result.status == "NETWORK_UNAVAILABLE") {
                        status(LIBXTUN_STATUS_NO_NETWORK);
                    }
                }
            }
        } catch (const std::exception &e) {
            log(e.what());
        } catch (...) {
            log("openvpn: unexpected connection failure");
        }
        requestStop();
        if (m_readerThread.joinable()) {
            m_readerThread.join();
        }
        // Keep OpenVPN3 Core refcount operations and its last packet handler destruction on the worker.
        m_client.reset();
        status(LIBXTUN_STATUS_DISCONNECTED);
    }
}
