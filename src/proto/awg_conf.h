#include "util/result.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <vector>
#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <sys/socket.h>
#endif

#ifndef AWG_CONF_H
#define AWG_CONF_H

namespace libxtun {
namespace proto {
namespace awg {

template<typename T>
using ResultParser = ResultGeneric<T, std::errc>;

template<typename T>
struct PlainField {
    T val;

    static ResultParser<PlainField<T>> fromConf(std::string_view str);
    std::string toUapi() const;
};

using Uint16Field = PlainField<uint16_t>;
using Uint32Field = PlainField<uint32_t>;

template<typename T>
struct RangeField {
    T lo;
    T hi;

    inline bool overlap(const RangeField& cmp) const;
    static ResultParser<RangeField<T>> fromConf(std::string_view str);
    std::string toUapi() const;
};

using Uint16Range = RangeField<uint16_t>;
using Uint32Range = RangeField<uint32_t>;

struct BoolField {
    bool val;

    static ResultParser<BoolField> fromConf(std::string_view str);
    std::string toUapi() const;
};

struct KeyField {
    static const int WG_KEY_SIZE = 32;
    std::array<uint8_t, WG_KEY_SIZE> bytes{};

    static ResultParser<KeyField> fromConf(std::string_view str);
    std::string toUapi() const;
};

struct IpAddrField {
    int family{AF_UNSPEC};
	union {
        struct in6_addr ip6;
		struct in_addr ip4;
	};

    static ResultParser<IpAddrField> fromConf(std::string_view str);
    std::string toUapi() const;
};

struct PrefixField {
    IpAddrField addr{};
    unsigned cidr{};

    static ResultParser<PrefixField> fromConf(std::string_view str);
    std::string toUapi() const;
};

struct EndpointField {
    IpAddrField addr{};
    uint16_t port{};

    static ResultParser<EndpointField> fromConf(std::string_view str);
    std::string toUapi() const;
};

struct StringField {
    std::string str;

    static ResultParser<StringField> fromConf(std::string_view str);
    std::string toUapi() const;
};

class Config {
  public:
    struct Peer {
        std::optional<EndpointField> endpoint;
        std::optional<KeyField> public_key;
        std::optional<KeyField> preshared_key;
        std::optional<Uint16Range> persistent_keepalive_interval;
        std::vector<PrefixField> allowed_ips;
    };
    struct Interface {
        // System params
        std::vector<IpAddrField> dns;
        std::optional<Uint32Field> mtu;
        std::optional<PrefixField> address;

        // WireGuard params
        std::optional<KeyField> private_key;
        std::optional<Uint32Field> fwmark;
        std::optional<Uint16Field> listen_port;

        // AWG params
        std::optional<Uint16Field> jc, jmin, jmax;
        std::optional<Uint16Field> s1, s2, s3, s4;
        std::optional<Uint32Field> h1, h2, h3, h4;
        std::optional<StringField> i1, i2, i3, i4, i5;
        std::optional<KeyField> header_protection_key;
        std::optional<Uint16Range> content_padding_addition, rekey_after_time,
            rekey_timeout, reject_after_time, keepalive_timeout,
            max_handshake_attempts;
        std::optional<BoolField> random_trailers;
        std::optional<BoolField> disable_cookies;

        std::vector<Peer> peers;
    };

    const Interface& iface() {
        return m_iface;
    }

    void setFwmark(uint32_t mark) {
        m_iface.fwmark = Uint32Field{mark};
    }

    Config(Interface iface) : m_iface(iface) {};
    static ResultXtun<Config> fromConf(const std::string& str);
    std::string toUapi() const;

  private:
    Interface m_iface{};
};

}
}
}

#endif
