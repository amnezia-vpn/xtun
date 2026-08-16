#include "proto/awg.h"
#include "proxy.h"
#include "xtun.h"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

bool privileged() {
    return ::geteuid() == 0;
}


constexpr const char *kPrivA = "YHJIKcg6kMlHqmHvpdetXH9300wKO4NxqX1L+v9h20A=";
constexpr const char *kPubA = "dpY/lgMy5OZPe6EVFl25AYL8hCsNEPxzO2uZZdzLnlo=";
constexpr const char *kPrivB = "CPbRqDXAuXNShMCXDVQ6d7mKeVAk2isLmqSNOnVWGWs=";
constexpr const char *kPubB = "sB1wCAUCSBg8mrN8n4mPMAs4Z2C9QUCu3i6Emfb9omo=";

constexpr int kPortA = 56811;
constexpr int kPortB = 56812;

constexpr const char *kAwgParams =
    "Jc = 2\n"
    "Jmin = 8\n"
    "Jmax = 16\n"
    "S1 = 4\n"
    "S2 = 6\n"
    "H1 = 1234567891\n"
    "H2 = 1234567892\n"
    "H3 = 1234567893\n"
    "H4 = 1234567894\n";

void logA(const char *str, void *) {
    std::fprintf(stderr, "[A] %s\n", str);
}

void logB(const char *str, void *) {
    std::fprintf(stderr, "[B] %s\n", str);
}

class MemTun {
  public:
    libxtun::ProxyIo io() {
        libxtun::ProxyIo io;
        io.read = [this](void *buf, int len) { return read(buf, len); };
        io.write = [this](const void *buf, int len) { return write(buf, len); };
        io.mtu = []() { return 1420; };
        return io;
    }

    void inject(const std::vector<unsigned char> &pkt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_in.push_back(pkt);
        m_cond.notify_all();
    }

    bool awaitDelivery(std::vector<unsigned char> &pkt, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (!m_cond.wait_for(lock, timeout, [this] { return !m_out.empty(); })) {
            return false;
        }
        pkt = std::move(m_out.front());
        m_out.pop_front();
        return true;
    }

    void cancel() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cancelled = true;
        m_cond.notify_all();
    }

  private:
    int read(void *buf, int len) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock, [this] { return m_cancelled || !m_in.empty(); });
        if (m_cancelled) {
            return -1;
        }
        std::vector<unsigned char> pkt = std::move(m_in.front());
        m_in.pop_front();
        int n = static_cast<int>(pkt.size());
        if (n > len) {
            n = len;
        }
        std::memcpy(buf, pkt.data(), n);
        return n;
    }

    int write(const void *buf, int len) {
        if (len < 0) {
            return -1;
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        const unsigned char *p = static_cast<const unsigned char *>(buf);
        m_out.emplace_back(p, p + len);
        m_cond.notify_all();
        return len;
    }

    std::mutex m_mutex;
    std::condition_variable m_cond;
    std::deque<std::vector<unsigned char>> m_in;
    std::deque<std::vector<unsigned char>> m_out;
    bool m_cancelled = false;
};

libxtun::proto::awg::Config confA() {;
    const std::string str = std::string("[Interface]\n") + "PrivateKey = " + kPrivA + "\n" +
        "ListenPort = " + std::to_string(kPortA) + "\n" + kAwgParams +
        "\n"
        "[Peer]\n" +
        "PublicKey = " + kPubB + "\n" + "Endpoint = 127.0.0.1:" + std::to_string(kPortB) +
        "\n"
        "AllowedIPs = 10.9.9.2/32\n"
        "PersistentKeepalive = 5\n";

    auto res = libxtun::proto::awg::Config::fromConf(str);
    return res.value();
}

libxtun::proto::awg::Config confB() {
    const std::string str = std::string("[Interface]\n") + "PrivateKey = " + kPrivB + "\n" +
        "ListenPort = " + std::to_string(kPortB) + "\n" + kAwgParams +
        "\n"
        "[Peer]\n" +
        "PublicKey = " + kPubA + "\n" + "Endpoint = 127.0.0.1:" + std::to_string(kPortA) +
        "\n"
        "AllowedIPs = 10.9.9.1/32\n";

    auto res = libxtun::proto::awg::Config::fromConf(str);
    return res.value();
}

std::vector<unsigned char> ipv4Packet(const char *payload) {
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

}  // namespace

TEST(AwgRoundtrip, DeliversDataBetweenTwoInstances) {
    libxtun_proxy cproxyA{};
    libxtun_proxy cproxyB{};
    cproxyA.loghandler = logA;
    cproxyB.loghandler = logB;

    MemTun tunA;
    MemTun tunB;

    libxtun::proto::Awg a(confA());
    libxtun::proto::Awg b(confB());

    a.bind(&cproxyA);
    b.bind(&cproxyB);

    ASSERT_EQ(a.start(tunA.io()), LIBXTUN_OK);
    ASSERT_EQ(b.start(tunB.io()), LIBXTUN_OK);

    a.event(libxtun::ProxyEvent::Up);
    b.event(libxtun::ProxyEvent::Up);

    std::vector<unsigned char> sent = ipv4Packet("xtun-ping");
    std::vector<unsigned char> got;
    bool delivered = false;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
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

TEST(AwgRoundtrip, StopUnblocksParkedReader) {
    ASSERT_TRUE(privileged()) << "AWG UAPI socket needs root (/var/run/amneziawg)";

    MemTun tun;

    libxtun::proto::Awg a(confA());
    ASSERT_EQ(a.start(tun.io()), LIBXTUN_OK);

    tun.cancel();
    a.stop();
}
