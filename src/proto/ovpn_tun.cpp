#include "ovpn_impl.h"

#include "io/remapping_io.h"
#include "net/ip.h"
#include "tunnel_io.h"

#include <limits>
#include <utility>

namespace libxtun::proto
{
    namespace
    {
        std::string profileError(libxtun_error rc)
        {
            if (rc == LIBXTUN_ERR_INVALID_ARGS) {
                return "openvpn: Tunnel rejected the local routes as invalid";
            }
            if (rc == LIBXTUN_ERR_UNSUPPORTED) {
                return "openvpn: Tunnel cannot apply local routes, or its listener was removed";
            }
            return "openvpn: applying local routes failed: " + std::to_string(rc);
        }

        bool isIpv4Packet(const openvpn::BufferAllocated &packet, int mtu)
        {
            if (mtu <= 0 || packet.size() < net::IpView::HEADER_LEN
                || packet.size() > static_cast<std::size_t>(mtu)) {
                return false;
            }
            const std::span<const std::byte> bytes(
                    reinterpret_cast<const std::byte *>(packet.c_data()), packet.size());
            const net::IpView ip(bytes.first<net::IpView::HEADER_LEN>());
            return ip.version() == 4 && ip.ihlBytes() >= net::IpView::HEADER_LEN
                    && ip.ihlBytes() <= packet.size() && ip.totalLen() == packet.size();
        }
    }

    // Bridges OpenVPN3 packets to Tunnel's existing TUN.
    // Remaps the TUN IPv4 address to the address assigned by the server.
    class Ovpn::Impl::OvpnTunClient final : public openvpn::TunClient
    {
    public:
        OvpnTunClient(Impl &impl, openvpn_io::io_context &context, openvpn::TunClientParent &parent,
                      const openvpn::ExternalTun::Config &conf)
            : m_impl(impl), m_context(context), m_parent(parent), m_conf(conf)
        {
        }

        ~OvpnTunClient() override
        {
            stop();
        }

        // Called on the Core worker with merged local and server options.
        void tun_start(const openvpn::OptionList &opt, openvpn::TransportClient &transport,
                       openvpn::CryptoDCSettings &) override
        {
            try {
                if (m_impl.m_stopping.load() || m_impl.m_readerThread.joinable()) {
                    throw std::runtime_error("openvpn: connection already stopped or TUN already started");
                }
                m_parent.tun_pre_tun_config();
                m_mtu = ovpn::configureSession(opt, m_conf, transport.server_endpoint_addr(),
                                              m_impl.m_proxy.tunMtu(), m_state);
                if (!m_conf.frame) {
                    throw std::runtime_error("openvpn: OpenVPN3 Core supplied no packet frame");
                }
                // Give the reader a copy of the buffer sizes, without copying m_conf.frame.
                // m_conf.frame is an OpenVPN3 smart pointer; copying/destroying it changes a reference counter.
                // That counter is not protected between threads, so keep the smart pointer on the worker.
                const auto frame = (*m_conf.frame)[openvpn::Frame::READ_TUN];
                if (frame.payload() < static_cast<std::size_t>(m_mtu)
                    || frame.payload() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                    throw std::runtime_error("openvpn: OpenVPN3 Core frame cannot hold the session MTU");
                }

                TunnelIo &io = m_impl.m_proxy.m_io;
                m_impl.m_sessionMtu.store(m_mtu);
                const int tunMtu = io.mtu();
                if (tunMtu <= 0) {
                    throw std::runtime_error("openvpn: existing TUN has no valid MTU");
                }
                if (tunMtu > m_mtu) {
                    throw std::runtime_error("openvpn: existing TUN MTU exceeds session MTU");
                }
                const auto addresses = io.addresses();
                const auto ipv4Count = std::count_if(addresses.begin(), addresses.end(), [](const auto &prefix) {
                    return prefix.address().family() == AF_INET;
                });
                if (ipv4Count != 1) {
                    throw std::runtime_error("openvpn: existing TUN must have exactly one IPv4 address");
                }
                const auto vpnAddress = net::IpAddress::parse(m_state.vpn_ip4_addr.to_string());
                if (!vpnAddress || vpnAddress->family() != AF_INET) {
                    throw std::runtime_error("openvpn: invalid assigned IPv4 address");
                }
                const net::IpPrefix vpnPrefix(*vpnAddress, 32);
                m_remapIo = RemappingIo::create(io, std::span<const net::IpPrefix>(&vpnPrefix, 1));
                m_packetIo = m_remapIo ? m_remapIo.get() : &io;

                ovpn::validateRoutes(m_impl.m_localProfile, transport.server_endpoint_addr());
                m_impl.log("openvpn: using routes and DNS metadata from the local config; "
                           "server route and DNS options are ignored");
                m_parent.tun_pre_route_config();
                if (auto rc = m_impl.applyProfile(m_impl.m_localProfile); rc != LIBXTUN_OK) {
                    throw std::runtime_error(profileError(rc));
                }
                if (m_impl.m_stopping.load()) {
                    throw std::runtime_error("openvpn: stopped while applying local routes");
                }
                // Create the reader before tun_connected(); if thread creation fails, the connection must fail.
                m_impl.m_readerThread = std::thread([this, frame]() { readPackets(frame); });
                if (m_impl.m_stopping.load()) {
                    throw std::runtime_error("openvpn: stopped while starting the TUN reader");
                }
                m_parent.tun_connected();
            } catch (const std::exception &e) {
                fail(openvpn::Error::TUN_SETUP_FAILED, e.what());
            } catch (...) {
                fail(openvpn::Error::TUN_SETUP_FAILED, "openvpn: unexpected TUN setup failure");
            }
        }

        void stop() override
        {
            m_packetQueue->deliveryEnabled.store(false);
            m_impl.requestStop();
            // OpenVPN3 calls stop() on the worker, which waits for the reader to finish.
            if (m_impl.m_readerThread.joinable() && m_impl.m_readerThread.get_id() != std::this_thread::get_id()) {
                m_impl.m_readerThread.join();
            }
        }

        void set_disconnect() override
        {
            // Tunnel owns the device, and this adapter does not keep TUN state for another connection.
        }

        bool tun_send(openvpn::BufferAllocated &packet) override
        {
            if (m_impl.m_stopping.load() || !m_packetQueue->deliveryEnabled.load() || !isIpv4Packet(packet, m_mtu)) {
                return false;
            }
            const auto size = static_cast<int>(packet.size());
            const int written = m_packetIo->write(
                    { reinterpret_cast<const std::byte *>(packet.c_data()), packet.size() });
            if (written != size) {
                // Each TUN write is a whole IP packet. Retrying the remaining bytes would create a broken packet.
                fail(openvpn::Error::TUN_HALT, "openvpn: TUN write failed or returned a short write");
                return false;
            }
            return true;
        }

        std::string tun_name() const override
        {
            return "xtun";
        }

        std::string vpn_ip4() const override
        {
            return m_state.vpn_ip4_addr.specified() ? m_state.vpn_ip4_addr.to_string() : "";
        }

        std::string vpn_ip6() const override
        {
            return "";
        }

        std::string vpn_gw4() const override
        {
            return m_state.vpn_ip4_gw.specified() ? m_state.vpn_ip4_gw.to_string() : "";
        }

        int vpn_mtu() const override
        {
            return m_mtu;
        }

        void apply_push_update(const openvpn::OptionList &, openvpn::TransportClient &) override
        {
            // This adapter does not apply settings changes during an active connection.
            fail(openvpn::Error::TUN_HALT, "openvpn: PUSH_UPDATE is not supported");
        }

    private:
        // Shared with the reader and queued handlers, which may outlive this TUN object.
        struct PacketQueue
        {
            // stop() disables delivery; queued handlers check this before using the TUN object.
            std::atomic<bool> deliveryEnabled { true };
            // Packets waiting for the worker; reader increments it and worker decrements it.
            std::atomic<unsigned> pendingPackets { 0 };
        };

        void fail(openvpn::Error::Type error, const std::string &reason)
        {
            // Keep this object alive until openvpn::TunClientParent::tun_error() returns.
            // keepAlive adds a temporary OpenVPN3 reference and releases it when fail() finishes.
            const openvpn::TunClient::Ptr keepAlive(this);
            m_impl.log(reason);
            m_impl.requestStop();
            m_parent.tun_error(error, reason);
        }

        void readPackets(const openvpn::Frame::Context &frame) noexcept
        {
            try {
                while (!m_impl.m_stopping.load() && m_packetQueue->deliveryEnabled.load()) {
                    auto packet = frame.alloc();
                    const int n = m_packetIo->read(
                            { reinterpret_cast<std::byte *>(packet.data()), frame.payload() });
                    if (m_impl.m_stopping.load() || !m_packetQueue->deliveryEnabled.load()) {
                        break;
                    }
                    if (n == READ_WAKE) {
                        continue;
                    }
                    if (n == IO_FATAL || n < 0 || static_cast<std::size_t>(n) > frame.payload()) {
                        m_impl.requestStop();
                        m_impl.log("openvpn: TUN read failed");
                        break;
                    }
                    // The I/O wrote n bytes; tell OpenVPN3 how many bytes are in this packet.
                    packet.set_size(static_cast<std::size_t>(n));
                    if (isIpv4Packet(packet, m_mtu)) {
                        postPacket(std::move(packet));
                    }
                }
            } catch (const std::exception &e) {
                m_impl.requestStop();
                m_impl.log(e.what());
            } catch (...) {
                m_impl.requestStop();
                m_impl.log("openvpn: unexpected TUN reader failure");
            }
        }

        // Called on the reader thread to sent an IP-packet to the queue of worker thread.
        void postPacket(openvpn::BufferAllocated packet)
        {
            // Queue at most 64 packets for the worker. Drop new packets when full to limit memory use.
            constexpr unsigned maxPendingPackets = 64;
            if (m_packetQueue->pendingPackets.fetch_add(1) >= maxPendingPackets) {
                m_packetQueue->pendingPackets.fetch_sub(1);
                return;
            }
            try {
                openvpn_io::post(m_context, [this, queue = m_packetQueue, packet = std::move(packet)]() mutable {
                    // The worker runs this function later; this packet is no longer waiting in the queue.
                    queue->pendingPackets.fetch_sub(1);
                    // stop() disables this flag; the TUN object may already be deleted when this runs.
                    // Check the shared flag before using this.
                    if (!queue->deliveryEnabled.load()) {
                        return;
                    }
                    deliverPacket(packet);
                });
            } catch (...) {
                // No queued handler was created, so undo the counter increment.
                m_packetQueue->pendingPackets.fetch_sub(1);
                throw;
            }
        }

        void deliverPacket(openvpn::BufferAllocated &packet)
        {
            // Keep this object alive while OpenVPN3 handles the packet and any resulting error.
            const openvpn::TunClient::Ptr keepAlive(this);
            if (m_impl.m_stopping.load()) {
                return;
            }
            // This runs on the worker; a catch in the reader cannot handle exceptions thrown on this thread.
            try {
                m_parent.tun_recv(packet);
            } catch (const std::exception &e) {
                fail(openvpn::Error::TUN_HALT, e.what());
            } catch (...) {
                fail(openvpn::Error::TUN_HALT, "openvpn: unexpected packet delivery failure");
            }
        }

        // Connection state, local route publishing, and access to Tunnel I/O.
        Impl &m_impl;
        // Used to queue packet handling on the OpenVPN3 worker thread.
        openvpn_io::io_context &m_context;
        // OpenVPN3 session that receives our packets and TUN setup/error notifications.
        openvpn::TunClientParent &m_parent;
        // Core settings for parsing session parameters and allocating packet buffers.
        openvpn::ExternalTun::Config m_conf;
        // Session address and gateway captured for remapping and Core callbacks.
        openvpn::TunProp::State m_state;
        // Effective MTU used to check packet sizes in both directions.
        int m_mtu = 0;
        // The reader is joined before this adapter and its address mapping are destroyed.
        std::unique_ptr<RemappingIo> m_remapIo;
        // Selects the mapping or the underlying AwaitingIo when the addresses already match.
        TunnelIo *m_packetIo = nullptr;
        // Keeps the delivery flag and packet count alive until all queued handlers are destroyed.
        std::shared_ptr<PacketQueue> m_packetQueue = std::make_shared<PacketQueue>();
    };

    // Creates OvpnTunClient with the TUN settings supplied by OpenVPN3.
    // OpenVPN3 calls this factory when it needs a TUN adapter for the connection.
    class Ovpn::Impl::OvpnTunFactory final : public openvpn::TunClientFactory
    {
    public:
        OvpnTunFactory(Impl &impl, const openvpn::ExternalTun::Config &conf) : m_impl(impl), m_conf(conf)
        {
        }

        openvpn::TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &context, openvpn::TunClientParent &parent,
                                                   openvpn::TransportClient *) override
        {
            return new OvpnTunClient(m_impl, context, parent, m_conf);
        }

        bool supports_epoch_data() override
        {
            // OpenVPN3 encrypts/decrypts data v3 packets; our adapter receives ordinary IP packets.
            return true;
        }

    private:
        // Connection that the new TUN adapter will use.
        Impl &m_impl;
        // OpenVPN3 TUN settings passed to each new adapter.
        openvpn::ExternalTun::Config m_conf;
    };

    openvpn::TunClientFactory *Ovpn::Impl::newTunFactory(const openvpn::ExternalTun::Config &conf)
    {
        if (conf.tun_prop.layer() != openvpn::Layer::OSI_LAYER_3 || conf.tun_persist) {
            ovpn::unsupported("TAP/layer 2 or persistent Core TUN");
        }
        if (m_stopping.load()) {
            throw std::runtime_error("openvpn: connection stopped before creating the TUN factory");
        }
        // OpenVPN3 takes this factory and deletes it when it is no longer needed.
        return new OvpnTunFactory(*this, conf);
    }
}
