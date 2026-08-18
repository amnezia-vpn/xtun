#include "xtun.h"

#include <gtest/gtest.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

bool privileged() {
#if defined(_WIN32)
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (::AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                   DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        ::CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        ::FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
#else
    return ::geteuid() == 0;
#endif
}

constexpr const char *kConf =
    "[Interface]\n"
    "PrivateKey = YHJIKcg6kMlHqmHvpdetXH9300wKO4NxqX1L+v9h20A=\n"
    "Jc = 2\n"
    "Jmin = 8\n"
    "Jmax = 16\n"
    "\n"
    "[Peer]\n"
    "PublicKey = sB1wCAUCSBg8mrN8n4mPMAs4Z2C9QUCu3i6Emfb9omo=\n"
    "Endpoint = 127.0.0.1:57777\n"
    "AllowedIPs = 10.99.0.2/32\n";

libxtun_tunnel_opts default_opts() {
    libxtun_tunnel_opts opts{};
    opts.size = sizeof(opts);
    opts.killswitch_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
    return opts;
}

}  // namespace

TEST(AwgTunnel, AttachAndTeardownTunnelFirst) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }

    libxtun_proxy proxy{};
    ASSERT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, kConf), LIBXTUN_OK);

    libxtun_tunnel_opts opts = default_opts();
    libxtun_tunnel tun{};
    ASSERT_EQ(libxtun_tunnel_new(&tun, &opts), LIBXTUN_OK);

    ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    libxtun_tunnel_free(&tun);
    libxtun_proxy_free(&proxy);
}

TEST(AwgTunnel, AttachAndTeardownProxyFirst) {
    if (!privileged()) {
        GTEST_SKIP() << "skipped: creating a tun device requires root/Administrator";
    }

    libxtun_proxy proxy{};
    ASSERT_EQ(libxtun_proxy_new(&proxy, LIBXTUN_PROXY_PROTO_AWG, kConf), LIBXTUN_OK);

    libxtun_tunnel_opts opts = default_opts();
    libxtun_tunnel tun{};
    ASSERT_EQ(libxtun_tunnel_new(&tun, &opts), LIBXTUN_OK);

    ASSERT_EQ(libxtun_tunnel_attach_proxy(&tun, &proxy), LIBXTUN_OK);

    libxtun_proxy_free(&proxy);
    libxtun_tunnel_free(&tun);
}
