#include "dns.h"
#include "tunnel.h"
#include "util/config.h"
#include "util/log.h"
#include "util/os.h"
#include "util/random.h"
#include "util/status.h"
#include "xtun.h"

#if defined(_WIN32)
    #include "dns_windows.h"

    #include <netioapi.h>
#else
    #include "util/spawn.h"
#endif

#include <chrono>
#include <cstddef>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    using libxtun::Proxy;
    using libxtun::Tunnel;
    using libxtun::test::Setup;
    using libxtun::test::SetupBuilder;
    using libxtun::test::TunOpts;

    const std::string ROUTED_DNS = "10.9.9.53";
    const std::string OFF_ROUTE_DNS = "192.0.2.53";
    const std::string TUNNEL_DEFAULT_DNS = "198.51.100.53";
    const std::string EXCEPTION_DNS = "203.0.113.53";
    const std::string FULL_ROUTE = "0.0.0.0/0";
    const std::string ROUTED_DNS_ROUTE = ROUTED_DNS + "/32";

#if defined(__linux__)
    const std::vector<std::string> ROUTING_DOMAINS { "~." };
#elif defined(__APPLE__)
    const std::vector<std::string> ROUTING_DOMAINS { "" };
#else
    const std::vector<std::string> ROUTING_DOMAINS;
#endif

    struct Resolvers
    {
        std::vector<std::string> servers;
        std::vector<std::string> domains;

        friend bool operator==(const Resolvers &, const Resolvers &) = default;
    };

    std::ostream &operator<<(std::ostream &out, const Resolvers &resolvers)
    {
        const auto list = [&out](const char *name, const std::vector<std::string> &items) {
            out << name << " [";
            for (const std::string &item : items) {
                out << " \"" << item << '"';
            }
            out << " ]";
        };
        list("servers", resolvers.servers);
        out << ", ";
        list("domains", resolvers.domains);
        return out;
    }

    Resolvers appliedResolvers(std::vector<std::string> servers)
    {
        std::vector<std::string> domains = servers.empty() ? std::vector<std::string> {} : ROUTING_DOMAINS;
        return { std::move(servers), std::move(domains) };
    }

    std::vector<std::string> split(const std::string &text, const char *separators)
    {
        std::vector<std::string> items;
        for (std::size_t start = text.find_first_not_of(separators); start != std::string::npos;) {
            const std::size_t end = text.find_first_of(separators, start);
            items.push_back(text.substr(start, end == std::string::npos ? end : end - start));
            start = text.find_first_not_of(separators, end);
        }
        return items;
    }

    Setup localSetup(std::vector<std::string> routes, std::vector<std::string> dns)
    {
        return SetupBuilder().withRoutes(std::move(routes)).withDns(std::move(dns)).build().front();
    }

#if defined(_WIN32)
    struct Adapter
    {
        int ifIndex = 0;
        GUID guid {};
    };

    std::optional<Adapter> adapterOf(const std::string &name)
    {
        const std::wstring alias(name.begin(), name.end());
        NET_LUID luid {};
        NET_IFINDEX index = 0;
        Adapter adapter;
        if (::ConvertInterfaceAliasToLuid(alias.c_str(), &luid) != NO_ERROR
            || ::ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR
            || ::ConvertInterfaceLuidToGuid(&luid, &adapter.guid) != NO_ERROR) {
            return std::nullopt;
        }
        adapter.ifIndex = static_cast<int>(index);
        return adapter;
    }

    std::optional<Resolvers> getTunResolvers(const std::string &tun)
    {
        const std::optional<Adapter> adapter = adapterOf(tun);
        if (!adapter) {
            return std::nullopt;
        }

        Resolvers resolvers;
        for (const bool ipv6 : { false, true }) {
            DNS_INTERFACE_SETTINGS settings {};
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
            settings.Flags = DNS_SETTING_NAMESERVER | (ipv6 ? DNS_SETTING_IPV6 : 0);
            if (::GetInterfaceDnsSettings(adapter->guid, &settings) != NO_ERROR) {
                return std::nullopt;
            }

            const std::wstring servers = settings.NameServer != nullptr ? settings.NameServer : L"";
            ::FreeInterfaceDnsSettings(&settings);
            std::string narrow;
            for (const wchar_t c : servers) {
                narrow.push_back(static_cast<char>(c));
            }
            for (const std::string &server : split(narrow, ", ")) {
                resolvers.servers.push_back(server);
            }
        }
        return resolvers;
    }
#elif defined(__APPLE__)
    std::optional<Resolvers> getTunResolvers(const std::string &tun)
    {
        const auto output = libxtun::spawn::run("/usr/sbin/scutil", {},
                                                "show State:/Network/Service/xtun-" + tun + "/DNS\nquit\n");
        if (!output) {
            return std::nullopt;
        }

        Resolvers resolvers;
        std::vector<std::string> *section = nullptr;
        std::istringstream lines(output.value());
        for (std::string line; std::getline(lines, line);) {
            const std::size_t first = line.find_first_not_of(" \t");
            if (first == std::string::npos) {
                continue;
            }
            line.erase(0, first);

            if (line.starts_with("ServerAddresses : <array>")) {
                section = &resolvers.servers;
            } else if (line.starts_with("SupplementalMatchDomains : <array>")) {
                section = &resolvers.domains;
            } else if (line.starts_with("}")) {
                section = nullptr;
            } else if (const std::size_t colon = line.find(':'); section != nullptr && colon != std::string::npos) {
                const std::string value = line.substr(colon + 1);
                const std::size_t begin = value.find_first_not_of(" \t");
                const std::size_t end = value.find_last_not_of(" \t\r");
                section->push_back(begin == std::string::npos ? std::string() : value.substr(begin, end - begin + 1));
            }
        }
        return resolvers;
    }
#else
    std::optional<std::vector<std::string>> resolvectl(const char *verb, const std::string &tun)
    {
        for (const char *path : { "/usr/bin/resolvectl", "/bin/resolvectl" }) {
            if (::access(path, X_OK) != 0) {
                continue;
            }

            const auto output = libxtun::spawn::run(path, { verb, tun }, {});
            const std::size_t colon = output ? output.value().find("):") : std::string::npos;
            if (colon == std::string::npos) {
                return std::nullopt;
            }
            return split(output.value().substr(colon + 2), " \t\r\n");
        }
        return std::nullopt;
    }

    std::optional<Resolvers> getTunResolvers(const std::string &tun)
    {
        auto servers = resolvectl("dns", tun);
        auto domains = resolvectl("domain", tun);
        if (!servers || !domains) {
            return std::nullopt;
        }
        return Resolvers { std::move(*servers), std::move(*domains) };
    }
#endif

    void expectResolvers(const Tunnel &tun, const Resolvers &expected)
    {
        const std::optional<Resolvers> actual = getTunResolvers(tun.name());
        ASSERT_TRUE(actual) << "could not read the resolvers of " << tun.name();
        EXPECT_EQ(*actual, expected);
    }

    class CountingDns final : public libxtun::Dns
    {
    public:
        int applies = 0;
        int reverts = 0;
        libxtun_error applyResult = LIBXTUN_OK;

    protected:
        libxtun_error applyResolvers(const std::vector<libxtun::net::IpAddress> &) override
        {
            ++applies;
            return applyResult;
        }

        void revertResolvers() noexcept override
        {
            ++reverts;
        }
    };
}

class DnsTunnel : public testing::Test
{
protected:
    void SetUp() override
    {
        if (!libxtun::test::privileged()) {
            GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
        }
        if (libxtun::Dns::create(1, "lo") == nullptr) {
            GTEST_SKIP() << "skipped: xtun can't configure DNS on this host";
        }
    }
};

TEST_F(DnsTunnel, ProxyResolversWinOverTunnelDefaults)
{
    const auto setup = localSetup({ ROUTED_DNS_ROUTE }, { ROUTED_DNS, OFF_ROUTE_DNS });
    TunOpts opts;
    opts.dns({ TUNNEL_DEFAULT_DNS }).dnsExceptions({ EXCEPTION_DNS });
    const auto proxy = Proxy::create(setup.proto, setup.clientA.c_str(), setup.wrapper->defaultCallbacks());
    ASSERT_TRUE(proxy) << proxy.error();
    const auto tun = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(tun) << tun.error();
    ASSERT_EQ(tun.value()->attachProxy(proxy.value().get()), LIBXTUN_OK);

    expectResolvers(*tun.value(), appliedResolvers({ ROUTED_DNS, OFF_ROUTE_DNS }));
}

TEST_F(DnsTunnel, TunnelDefaultsApplyWhenProxyHasNone)
{
    const auto setup = localSetup({ ROUTED_DNS_ROUTE }, {});
    TunOpts opts;
    opts.dns({ ROUTED_DNS });
    const auto proxy = Proxy::create(setup.proto, setup.clientA.c_str(), setup.wrapper->defaultCallbacks());
    ASSERT_TRUE(proxy) << proxy.error();
    const auto tun = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(tun) << tun.error();
    ASSERT_EQ(tun.value()->attachProxy(proxy.value().get()), LIBXTUN_OK);

    expectResolvers(*tun.value(), appliedResolvers({ ROUTED_DNS }));
}

TEST_F(DnsTunnel, NoResolversLeavesHostUntouched)
{
    const auto setup = localSetup({ ROUTED_DNS_ROUTE }, {});
    TunOpts opts;
    const auto proxy = Proxy::create(setup.proto, setup.clientA.c_str(), setup.wrapper->defaultCallbacks());
    ASSERT_TRUE(proxy) << proxy.error();
    const auto tun = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(tun) << tun.error();
    ASSERT_EQ(tun.value()->attachProxy(proxy.value().get()), LIBXTUN_OK);

    expectResolvers(*tun.value(), Resolvers {});
}

TEST_F(DnsTunnel, SwitchReplacesResolvers)
{
    const auto first = localSetup({ ROUTED_DNS_ROUTE }, { ROUTED_DNS, OFF_ROUTE_DNS });
    const auto second = localSetup({ ROUTED_DNS_ROUTE }, { ROUTED_DNS });
    TunOpts opts;
    const auto firstProxy = Proxy::create(first.proto, first.clientA.c_str(), first.wrapper->defaultCallbacks());
    ASSERT_TRUE(firstProxy) << firstProxy.error();
    const auto secondProxy = Proxy::create(second.proto, second.clientA.c_str(), second.wrapper->defaultCallbacks());
    ASSERT_TRUE(secondProxy) << secondProxy.error();
    const auto tun = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(tun) << tun.error();

    ASSERT_EQ(tun.value()->attachProxy(firstProxy.value().get()), LIBXTUN_OK);
    expectResolvers(*tun.value(), appliedResolvers({ ROUTED_DNS, OFF_ROUTE_DNS }));

    ASSERT_EQ(tun.value()->attachProxy(secondProxy.value().get()), LIBXTUN_OK);
    expectResolvers(*tun.value(), appliedResolvers({ ROUTED_DNS }));
}

TEST_F(DnsTunnel, DetachClearsResolvers)
{
    const auto setup = localSetup({ ROUTED_DNS_ROUTE }, { ROUTED_DNS, OFF_ROUTE_DNS });
    TunOpts opts;
    const auto proxy = Proxy::create(setup.proto, setup.clientA.c_str(), setup.wrapper->defaultCallbacks());
    ASSERT_TRUE(proxy) << proxy.error();
    const auto tun = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(tun) << tun.error();
    ASSERT_EQ(tun.value()->attachProxy(proxy.value().get()), LIBXTUN_OK);
    expectResolvers(*tun.value(), appliedResolvers({ ROUTED_DNS, OFF_ROUTE_DNS }));

    tun.value()->detachProxy(proxy.value().get());
    expectResolvers(*tun.value(), Resolvers {});
}

TEST_F(DnsTunnel, ResolvesThroughTunnel)
{
    for (const std::vector<std::string> &routes :
         { std::vector<std::string> { FULL_ROUTE }, std::vector<std::string> { ROUTED_DNS_ROUTE } }) {
        SCOPED_TRACE(routes.front());
        const auto setup = localSetup(routes, { ROUTED_DNS });
        const auto server = setup.createServer("server");
        ASSERT_NE(server, nullptr);

        libxtun::test::Logger log("client");
        libxtun::test::StatusChecker status;
        libxtun::ClientCallbacks callbacks = setup.wrapper->defaultCallbacks();
        log.wrapCallbacks(callbacks);
        status.wrapCallbacks(callbacks);

        TunOpts opts;
        const auto proxy = Proxy::create(setup.proto, setup.clientA.c_str(), callbacks);
        ASSERT_TRUE(proxy) << proxy.error();
        const auto tun = Tunnel::fromOpts(opts.get());
        ASSERT_TRUE(tun) << tun.error();
        ASSERT_EQ(tun.value()->attachProxy(proxy.value().get()), LIBXTUN_OK);
        ASSERT_TRUE(status.await(LIBXTUN_STATUS_CONNECTED, std::chrono::seconds(5)))
                << "the tunnel did not connect after attach";

        const std::string name = std::to_string(libxtun::rand::next32()) + ".xtun.test";
        const std::vector<std::string> addresses = libxtun::test::resolve(name);
        ASSERT_FALSE(addresses.empty()) << "could not resolve " << name;
        EXPECT_EQ(addresses.front(), ROUTED_DNS);
    }
}

TEST(DnsOpts, InvalidAddressIsRejected)
{
    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }

    {
        TunOpts opts;
        opts.dns({ TUNNEL_DEFAULT_DNS, "not-an-address" });
        const auto tun = Tunnel::fromOpts(opts.get());
        ASSERT_FALSE(tun) << "an invalid entry in dns was accepted";
        EXPECT_EQ(tun.error(), LIBXTUN_ERR_INVALID_ARGS);
    }
    {
        TunOpts opts;
        opts.dnsExceptions({ EXCEPTION_DNS, "not-an-address" });
        const auto tun = Tunnel::fromOpts(opts.get());
        ASSERT_FALSE(tun) << "an invalid entry in dns_exceptions was accepted";
        EXPECT_EQ(tun.error(), LIBXTUN_ERR_INVALID_ARGS);
    }
    {
        TunOpts opts;
        opts.dns({ TUNNEL_DEFAULT_DNS }).dnsExceptions({ EXCEPTION_DNS });
        const auto tun = Tunnel::fromOpts(opts.get());
        EXPECT_TRUE(tun) << "the same opts with valid entries were rejected";
    }
}

TEST(Dns, EqualSetChangesNothing)
{
    CountingDns dns;
    const std::vector<libxtun::net::IpAddress> x { *libxtun::net::IpAddress::parse("192.0.2.1") };
    const std::vector<libxtun::net::IpAddress> y { *libxtun::net::IpAddress::parse("192.0.2.2") };

    ASSERT_EQ(dns.apply(x), LIBXTUN_OK);
    ASSERT_EQ(dns.apply(x), LIBXTUN_OK);
    EXPECT_EQ(dns.applies, 1) << "an equal set was applied again";

    ASSERT_EQ(dns.apply(y), LIBXTUN_OK);
    EXPECT_EQ(dns.applies, 2);
    EXPECT_EQ(dns.reverts, 0) << "a different set was reverted before it was applied";

    dns.revert();
    ASSERT_EQ(dns.apply(y), LIBXTUN_OK);
    EXPECT_EQ(dns.applies, 3) << "a reverted set counted as applied";

    ASSERT_EQ(dns.apply({}), LIBXTUN_OK);
    EXPECT_EQ(dns.reverts, 2) << "an empty list did not revert";
    EXPECT_EQ(dns.applies, 3);

    dns.applyResult = LIBXTUN_ERR_DNS;
    EXPECT_EQ(dns.apply(x), LIBXTUN_ERR_DNS);
    dns.applyResult = LIBXTUN_OK;
    ASSERT_EQ(dns.apply(x), LIBXTUN_OK);
    EXPECT_EQ(dns.applies, 5) << "a failed set counted as applied";
}

#if defined(_WIN32)
TEST(DnsWindows, NetshFallbackWorks)
{
    if (!libxtun::test::privileged()) {
        GTEST_SKIP() << "skipped: creating an adapter requires Administrator";
    }

    TunOpts opts;
    const auto tun = Tunnel::fromOpts(opts.get());
    ASSERT_TRUE(tun) << tun.error();
    const std::optional<Adapter> adapter = adapterOf(tun.value()->name());
    ASSERT_TRUE(adapter) << "could not find the adapter " << tun.value()->name();

    libxtun::WindowsDns dns(adapter->ifIndex, adapter->guid, nullptr);
    const std::vector<libxtun::net::IpAddress> resolvers { *libxtun::net::IpAddress::parse(ROUTED_DNS),
                                                           *libxtun::net::IpAddress::parse("2001:db8::53") };
    ASSERT_EQ(dns.apply(resolvers), LIBXTUN_OK);
    expectResolvers(*tun.value(), Resolvers { { ROUTED_DNS, "2001:db8::53" }, {} });

    dns.revert();
    expectResolvers(*tun.value(), Resolvers {});
}
#endif
