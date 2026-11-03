#include "ovpn_impl.h"

#include <openvpn/client/dns.hpp>
#include <openvpn/tun/builder/capture.hpp>

namespace libxtun::proto::ovpn
{
    namespace
    {
        std::vector<net::IpAddress> makeDnsServers(const openvpn::DnsOptions &dns)
        {
            if (!dns.search_domains.empty()) {
                unsupported("DNS search domains");
            }
            std::vector<net::IpAddress> servers;
            for (const auto &[priority, entry] : dns.servers) {
                (void)priority;
                if (!entry.domains.empty() || entry.dnssec != openvpn::DnsServer::Security::Unset || !entry.sni.empty()
                    || (entry.transport != openvpn::DnsServer::Transport::Unset
                        && entry.transport != openvpn::DnsServer::Transport::Plain)) {
                    unsupported("DNS policy (only plain DNS server addresses can be exported)");
                }
                for (const auto &address : entry.addresses) {
                    if (address.port != 0 && address.port != 53) {
                        unsupported("DNS server port");
                    }
                    const auto ip = net::IpAddress::parse(address.address);
                    if (!ip || ip->family() != AF_INET) {
                        unsupported("IPv6 DNS server");
                    }
                    servers.push_back(*ip);
                }
            }
            return servers;
        }
    }

    ProxyProfile makeLocalProfile(const openvpn::OptionList &opt)
    {
        ProxyProfile profile;
        for (const auto &option : opt) {
            if (option.get(0, 64) != "route") {
                continue;
            }
            const auto route = openvpn::IP::AddrMaskPair::from_string(
                    option.get(1, 256), option.get_optional(2, 256), "route");
            const auto address = net::IpAddress::parse(route.addr.to_string());
            if (!address || address->family() != AF_INET || !route.is_canonical()) {
                throw std::runtime_error("openvpn: route must be a canonical IPv4 prefix");
            }
            profile.routes.emplace_back(*address, route.netmask.prefix_len());
        }
        if (opt.exists("redirect-gateway")) {
            // Router bypasses its policy default route for marked transport sockets.
            // Two main-table /1 routes would override the physical route even for those sockets.
            profile.routes.push_back(*net::IpPrefix::parse("0.0.0.0/0"));
        }

        const openvpn::TunProp::Config tunConfig;
        const openvpn::DnsOptionsParser dns(opt, tunConfig.dhcp_search_domains_as_split_domains);
        // Export local DNS addresses as metadata; Tunnel does not configure the system resolver.
        profile.dnsServers = makeDnsServers(dns);
        return profile;
    }

    void validateRoutes(const ProxyProfile &profile, const openvpn::IP::Addr &server)
    {
        const auto endpoint = net::IpAddress::parse(server.to_string());
        if (!endpoint || endpoint->family() != AF_INET) {
            throw std::runtime_error("openvpn: invalid IPv4 transport address");
        }
        for (const auto &route : profile.routes) {
            // SO_MARK bypasses Router's policy default route, but not main-table specific routes.
            if (!route.isDefaultRoute() && route.contains(*endpoint)) {
                throw std::domain_error("openvpn: local route " + route.toString() + " includes VPN server "
                                        + endpoint->toString()
                                        + "; this would route the VPN connection into its own tunnel");
            }
        }
    }

    int configureSession(const openvpn::OptionList &opt, const openvpn::ExternalTun::Config &conf,
                         const openvpn::IP::Addr &server, int initialMtu, openvpn::TunProp::State &state)
    {
        validateSessionOptions(opt);
        openvpn::OptionList sessionOptions;
        for (const auto &option : opt) {
            if (isOneOf(option.get(0, 64), { "ifconfig", "topology", "route-gateway", "tun-mtu" })) {
                sessionOptions.push_back(option);
            }
        }
        sessionOptions.update_map();

        // Capture session parameters without applying server routes, DNS, or interface settings to the OS.
        openvpn::TunBuilderCapture capture;
        openvpn::TunProp::configure_builder(&capture, &state, conf.stats.get(), server, conf.tun_prop,
                                            sessionOptions, nullptr, false);
        capture.validate();
        if (capture.layer() != openvpn::Layer::OSI_LAYER_3 || capture.tunnel_addresses.size() != 1
            || capture.tunnel_addresses.front().ipv6) {
            unsupported("session address family (one IPv4 TUN address is required)");
        }

        const int mtu = capture.mtu ? capture.mtu : std::min(initialMtu, conf.tun_prop.mtu_max);
        if (mtu < 68 || mtu > 65535) {
            throw std::runtime_error("openvpn: invalid effective session MTU");
        }
        return mtu;
    }
}
