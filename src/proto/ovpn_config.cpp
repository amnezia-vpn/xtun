#include "ovpn_impl.h"

#include <openvpn/client/cliconstants.hpp>

namespace libxtun::proto::ovpn
{
    namespace
    {
        // OpenVPN3 parses the profile; this list limits it to features implemented by Ovpn proxy.
        // OpenVPN3 accepts some unsupported script/OS directives with only a warning.
        bool supportedConfig(const openvpn::OptionList &opt, std::string &reason)
        {
            const auto *device = opt.get_ptr("dev-type");
            if (device == nullptr) {
                device = opt.get_ptr("dev");
            }
            if (device && device->get(1, 64).compare(0, 3, "tun") != 0) {
                reason = "openvpn: only TUN/layer 3 is supported";
                return false;
            }
            for (const auto &o : opt) {
                if (o.meta()) {
                    continue;
                }
                const auto &key = o.get(0, 64);
                if (!isOneOf(key,
                             { "client",
                               "tls-client",
                               "pull",
                               "dev",
                               "dev-type",
                               "proto",
                               "remote",
                               "port",
                               "remote-random",
                               "remote-random-hostname",
                               "resolv-retry",
                               "server-poll-timeout",
                               "connect-timeout",
                               "connect-retry",
                               "connect-retry-max",
                               "nobind",
                               "persist-key",
                               "persist-tun",
                               "ca",
                               "cert",
                               "key",
                               "extra-certs",
                               "crl-verify",
                               "tls-auth",
                               "key-direction",
                               "remote-cert-tls",
                               "remote-cert-ku",
                               "remote-cert-eku",
                               "verify-x509-name",
                               "tls-version-min",
                               "tls-version-max",
                               "tls-cipher",
                               "tls-ciphersuites",
                               "tls-cert-profile",
                               "tls-timeout",
                               "reneg-sec",
                               "reneg-bytes",
                               "reneg-pkts",
                               "auth",
                               "cipher",
                               "data-ciphers",
                               "data-ciphers-fallback",
                               "auth-nocache",
                               "tun-mtu",
                               "tun-mtu-max",
                               "mssfix",
                               "tcp-nodelay",
                               "verb",
                               "mute",
                               "mute-replay-warnings",
                               "explicit-exit-notify",
                               "push-peer-info",
                               "route",
                               "redirect-gateway",
                               "dhcp-option",
                               "dns",
                               "setenv" })) {
                    reason = "openvpn: unsupported configuration directive: " + key;
                    return false;
                }
                if (key == "setenv") {
                    const auto &name = o.get(1, 64);
                    if (!isOneOf(name, { "FRIENDLY_NAME", "PUSH_PEER_INFO" }) && name.compare(0, 3, "UV_") != 0
                        && !(name == "CLIENT_CERT" && o.get_optional(2, 16) == "1")) {
                        reason = "openvpn: unsupported setenv variable: " + name;
                        return false;
                    }
                }
                if (key == "proto" || (key == "remote" && o.size() >= 4)) {
                    const auto protocol = openvpn::Protocol::parse(o.get(key == "proto" ? 1 : 3, 32),
                                                                   openvpn::Protocol::CLIENT_SUFFIX);
                    if (protocol.is_ipv6() || (!protocol.is_udp() && !protocol.is_tcp())) {
                        reason = "openvpn: only UDP/TCP over IPv4 is supported";
                        return false;
                    }
                }
                if (key == "remote") {
                    if (auto address = net::IpAddress::parse(o.get(1, 256)); address && address->family() != AF_INET) {
                        reason = "openvpn: IPv6 remote addresses are not supported";
                        return false;
                    }
                }
            }
            return true;
        }

        void validateNetworkOptions(const openvpn::OptionList &opt)
        {
            for (const auto &o : opt) {
                const auto &key = o.get(0, 64);
                // "inactive" option is unsupported until OvpnTunClient updates OpenVPN3's TUN traffic counters.
                if (isOneOf(key,
                            { "ifconfig-ipv6", "route-ipv6", "redirect-private", "route-metric", "block-ipv4",
                              "block-ipv6", "block-outside-dns", "redirect-dns", "compress", "comp-lzo",
                              "inactive" })) {
                    unsupported(key);
                }
                if (key == "redirect-gateway") {
                    for (std::size_t i = 1; i < o.size(); ++i) {
                        if (!isOneOf(o.get(i, 64), { "def1", "ipv4", "!ipv6" })) {
                            unsupported("redirect-gateway " + o.get(i, 64));
                        }
                    }
                }
                if (key == "dhcp-option" && o.get(1, 64) != "DNS") {
                    unsupported("dhcp-option " + o.get(1, 64));
                }
                if (key == "route") {
                    if (o.size() > 4 || (o.size() == 4 && o.get(3, 256) != "vpn_gateway")) {
                        unsupported("route gateway or metric (only vpn_gateway without a metric is supported)");
                    }
                    // openvpn::TunProp logs and skips invalid routes.
                    const auto pair =
                            openvpn::IP::AddrMaskPair::from_string(o.get(1, 256), o.get_optional(2, 256), "route");
                    if (pair.version() != openvpn::IP::Addr::V4 || !pair.is_canonical()) {
                        throw std::runtime_error("openvpn: route must be a canonical IPv4 prefix");
                    }
                }
            }
        }
    }

    ProxyProfile parseLocalProfile(const std::string &content)
    {
        openvpn::OptionList opt;
        openvpn::OptionList::Limits limits(
                "openvpn: profile is too large", openvpn::ProfileParseLimits::MAX_PROFILE_SIZE,
                openvpn::ProfileParseLimits::OPT_OVERHEAD, openvpn::ProfileParseLimits::TERM_OVERHEAD,
                openvpn::ProfileParseLimits::MAX_LINE_SIZE, openvpn::ProfileParseLimits::MAX_DIRECTIVE_SIZE);

        // Read .ovpn options, including multiline <ca>, <cert>, and <key> blocks.
        opt.parse_from_config(content, &limits);
        // Read Access Server metadata from comments starting with "# OVPN_ACCESS_SERVER_".
        // TODO: remove this call later: we don't use Access Server
        opt.parse_meta_from_config(content, "OVPN_ACCESS_SERVER", &limits);
        // Build the lookup from an option name to its positions in the list.
        opt.update_map();

        for (const auto *key : { "ca", "cert", "key" }) {
            const auto *indices = opt.get_index_ptr(key);
            if (!indices || indices->size() != 1) {
                throw std::domain_error(std::string("openvpn: exactly one inline <") + key + "> block is required");
            }
            const auto &block = opt[indices->front()];
            const auto &blockContent = block.get(1, openvpn::Option::MULTILINE);
            if (blockContent.empty()) {
                throw std::domain_error(std::string("openvpn: exactly one inline <") + key + "> block is required");
            }
        }
        // Username/password authentication is excluded even when credentials are embedded.
        if (opt.exists("auth-user-pass")) {
            throw std::domain_error("openvpn: auth-user-pass is not supported");
        }
        std::string reason;
        if (!supportedConfig(opt, reason)) {
            throw std::domain_error(reason);
        }
        // Reject unsupported local network policies before opening a transport socket.
        validateNetworkOptions(opt);
        return makeLocalProfile(opt);
    }

    void validateSessionOptions(const openvpn::OptionList &opt)
    {
        // OpenVPN3 handles protocol options; the adapter captures only the session address and MTU.
        // Route and DNS options in this merged list never replace the local policy.
        for (const auto &o : opt) {
            const auto &key = o.get(0, 64);
            if (!isOneOf(key,
                         { "ifconfig",
                           "topology",
                           "route-gateway",
                           "tun-mtu",
                           "route",
                           "redirect-gateway",
                           "dhcp-option",
                           "dns",
                           "route-ipv6",
                           "redirect-private",
                           "route-metric",
                           "block-outside-dns",
                           "redirect-dns",
                           "cipher",
                           "auth",
                           "key-derivation",
                           "peer-id",
                           "protocol-flags",
                           "custom-control",
                           "ping",
                           "ping-restart",
                           "ping-exit",
                           "keepalive",
                           "explicit-exit-notify",
                           "auth-nocache",
                           "auth-token",
                           "auth-token-user",
                           "echo",
                           "client-ip",
                           "push-continuation" })) {
                unsupported("pushed directive " + key);
            }
        }
    }
}
