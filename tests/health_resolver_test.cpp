#include "health/resolver_pool.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

using libxtun::health::Reachability;
using libxtun::health::ResolverPool;

ResolverPool pool(const std::vector<std::string> &dns, const std::vector<std::string> &addresses,
                  const std::vector<std::string> &routes) {
    return ResolverPool(dns, addresses, routes);
}

std::string selected(const ResolverPool &resolvers, Reachability via) {
    const auto address = resolvers.select(via);
    return address ? address->toString() : std::string{};
}

const std::vector<std::string> kFullTunnel = {"0.0.0.0/0"};
const std::vector<std::string> kSplitTunnel = {"10.8.0.0/24", "192.168.9.0/24"};
const std::vector<std::string> kTunnelAddress = {"10.8.0.2/24"};

}  // namespace

TEST(HealthResolver, FullTunnelSelectsTheConfiguredResolver) {
    const auto resolvers = pool({"1.1.1.1"}, kTunnelAddress, kFullTunnel);

    EXPECT_EQ(selected(resolvers, Reachability::InsideTunnel), "1.1.1.1");
}

TEST(HealthResolver, SplitTunnelWithAnUnroutedResolverSelectsNothing) {
    const auto resolvers = pool({"1.1.1.1"}, kTunnelAddress, kSplitTunnel);

    EXPECT_FALSE(resolvers.select(Reachability::InsideTunnel).has_value())
        << "a resolver the tunnel does not carry was offered as an in-tunnel target";
}

TEST(HealthResolver, SplitTunnelUsesAnInternalResolverItActuallyRoutes) {
    const auto resolvers = pool({"10.8.0.1"}, kTunnelAddress, kSplitTunnel);

    EXPECT_EQ(selected(resolvers, Reachability::InsideTunnel), "10.8.0.1");
}

TEST(HealthResolver, PublicFallbackIsAdmissibleOnlyBehindADefaultRoute) {
    EXPECT_EQ(selected(pool({}, kTunnelAddress, kFullTunnel), Reachability::InsideTunnel),
              "1.1.1.1");

    EXPECT_FALSE(pool({}, kTunnelAddress, kSplitTunnel).select(Reachability::InsideTunnel))
        << "the public fallback was guessed into a split tunnel";
}

TEST(HealthResolver, InTunnelTargetNeedsALocalAddressOfItsFamily) {
    const std::vector<std::string> dual_default = {"0.0.0.0/0", "::/0"};
    const auto resolvers = pool({"2606:4700:4700::1111"}, kTunnelAddress, dual_default);

    EXPECT_EQ(selected(resolvers, Reachability::InsideTunnel), "1.1.1.1")
        << "a v6 target was selected with no v6 address to send from";
}

TEST(HealthResolver, InTunnelSelectsV6WhenTheTunnelHasAV6Address) {
    const std::vector<std::string> addresses = {"10.8.0.2/24", "fd00::2/64"};
    const std::vector<std::string> routes = {"::/0"};
    const auto resolvers = pool({"2606:4700:4700::1111"}, addresses, routes);

    EXPECT_EQ(selected(resolvers, Reachability::InsideTunnel), "2606:4700:4700::1111");
}

TEST(HealthResolver, ControlProbeFallsBackFromATunnelInternalResolver) {
    const std::vector<std::string> addresses = {"172.29.172.1/24"};
    const auto resolvers = pool({"172.29.172.254"}, addresses, kFullTunnel);

    EXPECT_EQ(selected(resolvers, Reachability::PhysicalInterface), "1.1.1.1")
        << "an AmneziaWG-internal resolver was probed from the physical interface";
}

TEST(HealthResolver, ControlProbeRejectsPrivateConfiguredResolvers) {
    EXPECT_EQ(selected(pool({"10.8.0.1"}, kTunnelAddress, kFullTunnel),
                       Reachability::PhysicalInterface),
              "1.1.1.1");
    EXPECT_EQ(selected(pool({"192.168.1.1"}, kTunnelAddress, kFullTunnel),
                       Reachability::PhysicalInterface),
              "1.1.1.1");
}

TEST(HealthResolver, ControlProbeNeverProbesOurOwnAddress) {
    const std::vector<std::string> addresses = {"1.1.1.1/32"};
    const auto resolvers = pool({"1.1.1.1"}, addresses, kFullTunnel);

    EXPECT_EQ(selected(resolvers, Reachability::PhysicalInterface), "8.8.8.8");
}

TEST(HealthResolver, ControlProbeIgnoresTheRouteSet) {
    const auto resolvers = pool({"8.8.8.8"}, kTunnelAddress, {});

    EXPECT_EQ(selected(resolvers, Reachability::PhysicalInterface), "8.8.8.8");
    EXPECT_FALSE(resolvers.select(Reachability::InsideTunnel).has_value());
}

TEST(HealthResolver, LocalAddressIsSelectedPerFamily) {
    const std::vector<std::string> addresses = {"10.8.0.2/24", "fd00::2/64"};
    const auto resolvers = pool({}, addresses, kFullTunnel);

    const auto v4 = resolvers.localAddressFor(AF_INET);
    const auto v6 = resolvers.localAddressFor(AF_INET6);
    ASSERT_TRUE(v4.has_value());
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(v4->toString(), "10.8.0.2");
    EXPECT_EQ(v6->toString(), "fd00::2");
}

TEST(HealthResolver, AdoptedDeviceWithNoOptionsHasNoLocalAddress) {
    const auto resolvers = pool({}, {}, kFullTunnel);

    EXPECT_FALSE(resolvers.localAddressFor(AF_INET).has_value());
    EXPECT_FALSE(resolvers.select(Reachability::InsideTunnel).has_value())
        << "an in-tunnel probe was offered a target with no source address";
    EXPECT_EQ(selected(resolvers, Reachability::PhysicalInterface), "1.1.1.1");
}

TEST(HealthResolver, UnparsableEntriesAreSkippedRatherThanFatal) {
    const std::vector<std::string> dns = {"not-an-address", "8.8.8.8"};
    const auto resolvers = pool(dns, kTunnelAddress, kFullTunnel);

    EXPECT_EQ(selected(resolvers, Reachability::InsideTunnel), "8.8.8.8");
}
