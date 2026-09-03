#include "memtun.h"
#include "proto/awg.h"
#include "proxy.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#if defined(_WIN32)
    #include <winsock2.h>
#else
    #include <sys/socket.h>
#endif

namespace
{

    constexpr bool VERBOSE = false;

    constexpr const char *PRIV_KEY_A = "YHJIKcg6kMlHqmHvpdetXH9300wKO4NxqX1L+v9h20A=";
    constexpr const char *PUB_KEY_A = "dpY/lgMy5OZPe6EVFl25AYL8hCsNEPxzO2uZZdzLnlo=";
    constexpr const char *PRIV_KEY_B = "CPbRqDXAuXNShMCXDVQ6d7mKeVAk2isLmqSNOnVWGWs=";
    constexpr const char *PUB_KEY_B = "sB1wCAUCSBg8mrN8n4mPMAs4Z2C9QUCu3i6Emfb9omo=";

    constexpr int PORT_A = 56811;
    constexpr int PORT_B = 56812;

    constexpr const char *AWG_PARAMS = "Jc = 2\n"
                                       "Jmin = 8\n"
                                       "Jmax = 16\n"
                                       "S1 = 4\n"
                                       "S2 = 6\n"
                                       "H1 = 1234567891\n"
                                       "H2 = 1234567892\n"
                                       "H3 = 1234567893\n"
                                       "H4 = 1234567894\n";

    void logA(const char *str, void *)
    {
        if (VERBOSE) {
            std::fprintf(stderr, "[A] %s\n", str);
        }
    }

    void logB(const char *str, void *)
    {
        if (VERBOSE) {
            std::fprintf(stderr, "[B] %s\n", str);
        }
    }

    bool liveSocket(int fd)
    {
        sockaddr_storage ss {};
#if defined(_WIN32)
        int len = sizeof(ss);
        return ::getsockname(static_cast<SOCKET>(fd), reinterpret_cast<sockaddr *>(&ss), &len) == 0;
#else
        socklen_t len = sizeof(ss);
        return ::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &len) == 0;
#endif
    }

    class SocketRecorder
    {
    public:
        struct Offer
        {
            int fd = -1;
            bool live = false;
        };

        static void handler(int fd, void *priv)
        {
            auto *self = static_cast<SocketRecorder *>(priv);
            std::lock_guard<std::mutex> lock(self->m_mutex);
            self->m_offers.push_back({ fd, liveSocket(fd) });
        }

        std::vector<Offer> offers() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_offers;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<Offer> m_offers;
    };

    libxtun::proto::awg::Config confA()
    {
        ;
        const std::string str = std::string("[Interface]\n") + "PrivateKey = " + PRIV_KEY_A + "\n"
                + "ListenPort = " + std::to_string(PORT_A) + "\n" + AWG_PARAMS
                + "\n"
                  "[Peer]\n"
                + "PublicKey = " + PUB_KEY_B + "\n" + "Endpoint = 127.0.0.1:" + std::to_string(PORT_B)
                + "\n"
                  "AllowedIPs = 10.9.9.2/32\n"
                  "PersistentKeepalive = 5\n";

        auto res = libxtun::proto::awg::Config::fromConf(str);
        return res.value();
    }

    libxtun::proto::awg::Config confB()
    {
        const std::string str = std::string("[Interface]\n") + "PrivateKey = " + PRIV_KEY_B + "\n"
                + "ListenPort = " + std::to_string(PORT_B) + "\n" + AWG_PARAMS
                + "\n"
                  "[Peer]\n"
                + "PublicKey = " + PUB_KEY_A + "\n" + "Endpoint = 127.0.0.1:" + std::to_string(PORT_A)
                + "\n"
                  "AllowedIPs = 10.9.9.1/32\n";

        auto res = libxtun::proto::awg::Config::fromConf(str);
        return res.value();
    }

    std::vector<unsigned char> ipv4Packet(const char *payload)
    {
        size_t plen = std::strlen(payload);
        std::vector<unsigned char> p(20 + plen, 0);

        p[0] = 0x45;
        p[2] = static_cast<unsigned char>(p.size() >> 8);
        p[3] = static_cast<unsigned char>(p.size() & 0xff);
        p[8] = 64;
        p[9] = 253;
        p[12] = 10;
        p[13] = 9;
        p[14] = 9;
        p[15] = 1;
        p[16] = 10;
        p[17] = 9;
        p[18] = 9;
        p[19] = 2;
        std::memcpy(p.data() + 20, payload, plen);
        return p;
    }

} // namespace

TEST(AwgRoundtrip, DeliversDataBetweenTwoInstances)
{
    libxtun::ClientCallbacks callbacksA {};
    libxtun::ClientCallbacks callbacksB {};
    callbacksA.onLog = logA;
    callbacksB.onLog = logB;

    MemTun tunA;
    MemTun tunB;

    libxtun::proto::Awg a(confA());
    libxtun::proto::Awg b(confB());

    a.bind(callbacksA);
    b.bind(callbacksB);

    a.setInterface("xtuna");
    b.setInterface("xtunb");

    ASSERT_EQ(a.start(tunA), LIBXTUN_OK);
    ASSERT_EQ(b.start(tunB), LIBXTUN_OK);

    a.event(libxtun::ProxyEvent::Up);
    b.event(libxtun::ProxyEvent::Up);

    std::vector<unsigned char> sent = ipv4Packet("xtun-ping");
    std::vector<unsigned char> got;
    bool delivered = false;

    // Long enough for one handshake retransmit: an initiation that reaches a peer
    // which is not running yet is dropped, and RekeyTimeout is 5s.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!delivered && std::chrono::steady_clock::now() < deadline) {
        tunA.inject(sent);
        delivered = tunB.awaitDelivery(got, std::chrono::milliseconds(250));
    }

    tunA.cancel();
    tunB.cancel();
    a.stop();
    b.stop();

    ASSERT_TRUE(delivered) << "no packet arrived at peer B within the timeout";
    EXPECT_EQ(got, sent);
}

TEST(AwgRoundtrip, OffersSpawnedSocketsForProtection)
{
    SocketRecorder recorder;

    libxtun::ClientCallbacks callbacksA {};
    libxtun::ClientCallbacks callbacksB {};
    callbacksA.onLog = logA;
    callbacksB.onLog = logB;
    callbacksA.onSocket = &SocketRecorder::handler;
    callbacksA.onSocketPriv = &recorder;

    MemTun tunA;
    MemTun tunB;

    libxtun::proto::Awg a(confA());
    libxtun::proto::Awg b(confB());

    a.bind(callbacksA);
    b.bind(callbacksB);

    a.setInterface("xtuna");
    b.setInterface("xtunb");

    ASSERT_EQ(a.start(tunA), LIBXTUN_OK);
    ASSERT_EQ(b.start(tunB), LIBXTUN_OK);

    a.event(libxtun::ProxyEvent::Up);
    b.event(libxtun::ProxyEvent::Up);

    std::vector<unsigned char> sent = ipv4Packet("xtun-sockspawn");
    std::vector<unsigned char> got;
    bool delivered = false;

    // Long enough for one handshake retransmit: an initiation that reaches a peer
    // which is not running yet is dropped, and RekeyTimeout is 5s.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!delivered && std::chrono::steady_clock::now() < deadline) {
        tunA.inject(sent);
        delivered = tunB.awaitDelivery(got, std::chrono::milliseconds(250));
    }

    const std::vector<SocketRecorder::Offer> offered = recorder.offers();

    tunA.cancel();
    tunB.cancel();
    a.stop();
    b.stop();

    ASSERT_TRUE(delivered) << "no packet arrived at peer B within the timeout";
    ASSERT_FALSE(offered.empty()) << "onsockspawn never fired for the proxy's own sockets";
    for (const SocketRecorder::Offer &offer : offered) {
        EXPECT_TRUE(offer.live) << "descriptor " << offer.fd << " was not a live socket when it was offered";
    }
}

TEST(AwgRoundtrip, StopUnblocksParkedReader)
{
    MemTun tun;

    libxtun::proto::Awg a(confA());
    a.setInterface("xtuna");
    ASSERT_EQ(a.start(tun), LIBXTUN_OK);

    tun.cancel();
    a.stop();
}
