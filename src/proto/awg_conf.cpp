#include "awg_conf.h"

#include "util/reflect.h"

#include <arpa/inet.h>
#include <iomanip>
#include <ranges>
#include <charconv>
#include <sstream>
#include <string>
#include <sys/socket.h>

namespace libxtun {
namespace proto {
namespace awg {

template struct PlainField<uint16_t>;
template struct PlainField<uint32_t>;

template<typename T>
ResultParser<PlainField<T>> PlainField<T>::fromConf(const std::string_view str) {
    const char* end = str.data() + str.size();
    PlainField<T> field;

    const auto [p, ec] = std::from_chars(str.data(), end, field.val);
    if (ec != std::errc{})
        return fail(ec);
    if (p != end)
        return fail(std::errc::invalid_argument);
    return field;
}

template<typename T>
std::string PlainField<T>::toUapi() const {
    return std::to_string(val);
}

template struct RangeField<uint16_t>;
template struct RangeField<uint32_t>;

template<typename T>
inline bool RangeField<T>::overlap(const RangeField<T>& cmp) const {
    return lo <= cmp.hi && cmp.lo <= hi;
}

template<typename T>
ResultParser<RangeField<T>> RangeField<T>::fromConf(const std::string_view str) {
    const auto* const end = str.data() + str.size();
    T lo{}, hi{};

    const auto [p, ec] = std::from_chars(str.data(), end, lo);
    if (ec != std::errc{})
        return fail(ec);
    if (p == end)
        return RangeField{lo, lo};

    if (*p != '-')
        return fail(std::errc::invalid_argument);

    const auto [q, ec2] = std::from_chars(p + 1, end, hi);
    if (ec2 != std::errc{})
        return fail(ec2);
    if (q != end || lo > hi)
        return fail(std::errc::invalid_argument);
    return RangeField{lo, hi};
}

template<typename T>
std::string RangeField<T>::toUapi() const {
    std::ostringstream ss;
    ss << lo;
    if (lo != hi)
        ss << '-' << hi;
    return ss.str();
}

ResultParser<BoolField> BoolField::fromConf(const std::string_view str) {
    if (str == "on")
        return BoolField{true};
    else if (str == "off")
        return BoolField{false};
    else
        return fail(std::errc::invalid_argument);
}

std::string BoolField::toUapi() const {
    return val ? "1" : "0";
}

ResultParser<KeyField> KeyField::fromConf(const std::string_view str) {
    static constexpr char pad = '=';
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<uint8_t> bytes;
    int buffer = 0, bits = 0;
    for (char c : str) {
        if (c == pad)
            break;
        int d = val(c);
        if (d < 0)
            return fail(std::errc::invalid_argument);
        buffer = (buffer << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }

    if (bytes.size() != WG_KEY_SIZE)
        return fail(std::errc::invalid_argument);

    KeyField field;
    std::copy(bytes.begin(), bytes.end(), field.bytes.begin());
    return field;
}

std::string KeyField::toUapi() const {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (std::uint8_t b : bytes)
        ss << std::setw(2) << static_cast<unsigned>(b);
    return ss.str();
}

ResultParser<IpAddrField> IpAddrField::fromConf(std::string_view str) {
    std::string s(str);
    IpAddrField field{};

    if (inet_pton(AF_INET, s.c_str(), &field.ip4) == 1) {
        field.family = AF_INET;
        return field;
    }
    if (inet_pton(AF_INET6, s.c_str(), &field.ip6) == 1) {
        field.family = AF_INET6;
        return field;
    }
    return fail(std::errc::invalid_argument);
}

std::string IpAddrField::toUapi() const {
    char buf[INET6_ADDRSTRLEN + 1]{};
    if (family == AF_INET)
        return inet_ntop(AF_INET, &ip4, buf, INET6_ADDRSTRLEN);
    else if (family == AF_INET6)
        return inet_ntop(AF_INET6, &ip6, buf, INET6_ADDRSTRLEN);
    else
        return "";
}

ResultParser<PrefixField> PrefixField::fromConf(std::string_view str) {
    PrefixField field;

    auto slash = str.find('/');
    std::string_view addr_part = (slash == std::string_view::npos) ? str : str.substr(0, slash);

    auto res = IpAddrField::fromConf(addr_part);
    if (!res)
        return fail(res.error());
    field.addr = std::move(res).value();

    const unsigned maxCidr = (field.addr.family == AF_INET) ? 32u : 128u;
    if (slash == std::string_view::npos) {
        field.cidr = maxCidr;
        return field;
    }

    std::string_view cidr_part = str.substr(slash + 1);
    const char* end = cidr_part.data() + cidr_part.size();

    auto [p, ec] =
        std::from_chars(cidr_part.data(), end, field.cidr);
    if (ec != std::errc{})
        return fail(ec);
    if (p != end)
        return fail(std::errc::invalid_argument);
    if (field.cidr > maxCidr)
        return fail(std::errc::result_out_of_range);
    return field;
}

std::string PrefixField::toUapi() const {
    std::ostringstream ss;
    ss << addr.toUapi() << '/' << cidr;
    return ss.str();
}

ResultParser<EndpointField> EndpointField::fromConf(std::string_view str) {
    EndpointField field{};
    std::string_view addr_part;
    std::string_view port_part;

    if (!str.empty() && str.front() == '[') {
        auto close = str.find(']');
        if (close == std::string_view::npos)
            return fail(std::errc::invalid_argument);
        addr_part = str.substr(1, close - 1);
        std::string_view rest = str.substr(close + 1);
        if (rest.empty() || rest.front() != ':')
            return fail(std::errc::invalid_argument);
        port_part = rest.substr(1);
    } else {
        auto colon = str.find(':');
        if (colon == std::string_view::npos)
            return fail(std::errc::invalid_argument);
        addr_part = str.substr(0, colon);
        port_part = str.substr(colon + 1);
    }

    auto res = IpAddrField::fromConf(addr_part);
    if (!res)
        return fail(res.error());
    field.addr = std::move(res).value();

    const char* end = port_part.data() + port_part.size();
    auto [p, ec] = std::from_chars(port_part.data(), end, field.port);
    if (ec != std::errc{})
        return fail(ec);
    if (p != end)
        return fail(std::errc::invalid_argument);
    return field;
}

std::string EndpointField::toUapi() const {
    std::ostringstream ss;
    if (addr.family == AF_INET)
        ss << addr.toUapi();
    else if (addr.family == AF_INET6)
        ss << '[' << addr.toUapi() << ']';
    ss << ':' << port;
    return ss.str();
}

ResultParser<StringField> StringField::fromConf(std::string_view str) {
    return StringField{.str = std::string(str)};
}

std::string StringField::toUapi() const {
    return str;
};

namespace {
    std::string_view trim(std::string_view sv) {
        const char* ws = " \t\r\n";
        auto b = sv.find_first_not_of(ws);
        if (b == std::string_view::npos) return {};
        auto e = sv.find_last_not_of(ws);
        return sv.substr(b, e - b + 1);
    }

    template<auto M>
    std::errc fromConf(reflect::owner_t<M>& owner, std::string_view str) {
        using slot = reflect::slot_t<M>;
        if constexpr (reflect::is_vector_v<slot>) {
            for (auto range : str | std::views::split(',')) {
                auto part = trim(std::string_view(range.begin(), range.end()));
                auto res = reflect::field_t<reflect::slot_t<M>>::fromConf(part);
                if (!res)
                    return res.error();
                (owner.*M).emplace_back(std::move(res).value());
            }
            return std::errc{};    
        } else {
            auto res = reflect::field_t<slot>::fromConf(str);
            if (!res)
                return res.error();
            owner.*M = std::move(res).value();
            return std::errc{};
        }
    }

    template<auto M, reflect::fixed_string key>
    std::string toUapi(const reflect::owner_t<M>& owner) {
        if constexpr (key.empty()) {
            return {};
        } else {
            std::ostringstream ss;
            using slot = reflect::slot_t<M>;
            if constexpr (reflect::is_vector_v<slot>) {
                for (const auto& item : (owner.*M))
                    ss << key.data << "=" << item.toUapi() << '\n';
            } else if constexpr (reflect::is_optional_v<slot>) {
                if (owner.*M)
                    ss << key.data << "=" << (owner.*M)->toUapi() << '\n';
            } else {
                ss << key.data << "=" << (owner.*M).toUapi() << '\n';
            }
            return ss.str();
        }
    }

    template<typename T>
    struct Item {
        std::string_view confKey;
        std::errc (*fromConf)(T& owner, std::string_view str);
        std::string (*toUapi)(const T& owner);
    };

    template<auto M, reflect::fixed_string conf, reflect::fixed_string uapi>
    consteval Item<reflect::owner_t<M>> item() {
        return {
            .confKey = conf.data,
            .fromConf = &fromConf<M>,
            .toUapi = &toUapi<M, uapi>,
        };
    }

    inline constexpr std::array IFACE_ITEMS = {
        item<&Config::Interface::dns, "DNS", "">(),
        item<&Config::Interface::mtu, "MTU", "">(),
        item<&Config::Interface::address, "Address", "">(),
        item<&Config::Interface::private_key, "PrivateKey", "private_key">(),
        item<&Config::Interface::fwmark, "FwMark", "fwmark">(),
        item<&Config::Interface::listen_port, "ListenPort", "listen_port">(),
        item<&Config::Interface::jc, "Jc", "jc">(),
        item<&Config::Interface::jmin, "Jmin", "jmin">(),
        item<&Config::Interface::jmax, "Jmax", "jmax">(),
        item<&Config::Interface::s1, "S1", "s1">(),
        item<&Config::Interface::s2, "S2", "s2">(),
        item<&Config::Interface::s3, "S3", "s3">(),
        item<&Config::Interface::s4, "S4", "s4">(),
        item<&Config::Interface::h1, "H1", "h1">(),
        item<&Config::Interface::h2, "H2", "h2">(),
        item<&Config::Interface::h3, "H3", "h3">(),
        item<&Config::Interface::h4, "H4", "h4">(),
        item<&Config::Interface::i1, "I1", "i1">(),
        item<&Config::Interface::i2, "I2", "i2">(),
        item<&Config::Interface::i3, "I3", "i3">(),
        item<&Config::Interface::i4, "I4", "i4">(),
        item<&Config::Interface::i5, "I5", "i5">(),
        item<&Config::Interface::header_protection_key, "HeaderProtectionKey", "header_protection_key">(),
        item<&Config::Interface::content_padding_addition, "ContentPaddingAddition", "content_padding_addition">(),
        item<&Config::Interface::rekey_after_time, "RekeyAfterTime", "rekey_after_time">(),
        item<&Config::Interface::rekey_timeout, "RekeyTimeout", "rekey_timeout">(),
        item<&Config::Interface::reject_after_time, "RejectAfterTime", "reject_after_time">(),
        item<&Config::Interface::keepalive_timeout, "KeepaliveTimeout", "keepalive_timeout">(),
        item<&Config::Interface::max_handshake_attempts, "MaxHandshakeAttempts", "max_handshake_attempts">(),
        item<&Config::Interface::random_trailers, "RandomTrailers", "random_trailers">(),
        item<&Config::Interface::disable_cookies, "DisableCookies", "disable_cookies">(),
    };

    inline constexpr std::array PEER_ITEMS = {
        item<&Config::Peer::public_key, "PublicKey", "public_key">(),
        item<&Config::Peer::endpoint, "Endpoint", "endpoint">(),
        item<&Config::Peer::preshared_key, "PresharedKey", "preshared_key">(),
        item<&Config::Peer::persistent_keepalive_interval, "PersistentKeepalive", "persistent_keepalive_interval">(),
        item<&Config::Peer::allowed_ips, "AllowedIPs", "allowed_ip">(),
    };

    bool keysEqual(std::string_view a, std::string_view b) {
        constexpr auto lower = [](unsigned char c) { return std::tolower(c); };
        return std::ranges::equal(a, b, {}, lower, lower);
    }

    template<typename T, size_t N>
    std::errc lookupAndParse(const std::array<Item<T>, N>& table, T& owner, std::string_view key, std::string_view val) {
        for (const auto& it : table) {
            if (keysEqual(it.confKey, key))
                return it.fromConf(owner, val);
        }
        return std::errc::invalid_argument;
    }
}

ResultXtun<Config> Config::fromConf(const std::string& str) {
    std::istringstream ss(str);
    std::string line;

    Config::Interface iface{};
    Config::Peer *peer = nullptr;

    while(std::getline(ss, line)) {
        const auto sline = trim(line);

        // skip comments and empty strings
        if (sline.empty() || sline.front() == ';' || sline.front() == '#')
            continue;

        if (sline == "[Interface]") {
            peer = nullptr;
            continue;
        }
        if (sline == "[Peer]") {
            peer = &iface.peers.emplace_back(Config::Peer{});
            continue;
        }

        auto eq = sline.find('=');
        if (eq == std::string::npos)
            return fail(LIBXTUN_ERR_INVALID_ARGS);

        const auto key = trim(sline.substr(0, eq));
        const auto val = trim(sline.substr(eq + 1));

        auto res = peer == nullptr
            ? lookupAndParse(IFACE_ITEMS, iface, key, val)
            : lookupAndParse(PEER_ITEMS, *peer, key, val);
        if (res != std::errc{})
            return fail(LIBXTUN_ERR_INVALID_ARGS);
    }

    return Config(iface);
}

std::string Config::toUapi() const {
    std::stringstream ss;

    for (auto it : IFACE_ITEMS)
        ss << it.toUapi(m_iface);

    for (auto const &peer: m_iface.peers)
        for (auto it : PEER_ITEMS)
            ss << it.toUapi(peer);

    ss << '\n';
    return ss.str();
}

}
}
}
