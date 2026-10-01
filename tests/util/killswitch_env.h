#ifndef TEST_KILLSWITCH_ENV_H
#define TEST_KILLSWITCH_ENV_H

#include "killswitch.h"
#include "tun_device.h"
#include "util/noncopyable.h"
#include "xtun.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

#include "gtest/gtest.h"

namespace libxtun::test
{
    constexpr const char *TEST_NET_V4 = "203.0.113.1";
    constexpr const char *TEST_NET_V6 = "2001:db8::1";
    constexpr const char *TEST_NET_V6_PREFIX = "2001:db8::/32";
    constexpr const char *IPV6_PATH_ADDRESS = "fd00:10::2/64";
    constexpr const char *LOOPBACK_V4 = "127.0.0.1";
    constexpr std::uint16_t PROBE_PORT = 53;

    inline bool sh(const std::string &cmd)
    {
#if defined(_WIN32)
        return std::system((cmd + " >NUL 2>&1").c_str()) == 0;
#else
        return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0;
#endif
    }

    enum class Bypass {
        None,
        Proxy
    };

    enum class ProbeResult {
        Delivered,
        Blocked
    };

    inline std::ostream &operator<<(std::ostream &out, Bypass bypass)
    {
        return out << (bypass == Bypass::None ? "not exempt" : "proxy-marked");
    }

    inline std::ostream &operator<<(std::ostream &out, ProbeResult result)
    {
        return out << (result == ProbeResult::Delivered ? "delivered" : "blocked");
    }

    class KillswitchEnv : private NonCopyable
    {
    public:
        KillswitchEnv();
        ~KillswitchEnv();

        [[nodiscard]] std::string_view skipReason() const noexcept
        {
            return m_skipReason;
        }
        [[nodiscard]] std::unique_ptr<Killswitch> create(libxtun_killswitch_mode mode) const;
        [[nodiscard]] int ruleCount() const;
        [[nodiscard]] std::optional<ProbeResult> probe(const std::string &host, Bypass bypass) const;

    private:
        std::string m_skipReason;
        int m_ifIndex = 0;
        std::string m_ifName;
#if defined(__linux__)
        int m_netnsFd = -1;
#elif defined(__APPLE__)
        int m_ipv6TunFd = -1;
#elif defined(_WIN32)
        std::unique_ptr<TunDevice> m_ipv6Path;
#endif
    };

    class KillswitchTest : public testing::Test
    {
    protected:
        void SetUp() override
        {
            if (!m_env.skipReason().empty()) {
                GTEST_SKIP() << "skipped: " << m_env.skipReason();
            }
        }
        void expectProbeResult(const std::string &host, Bypass bypass, ProbeResult wanted, std::string_view phase = {})
        {
            if (const std::optional<ProbeResult> result = m_env.probe(host, bypass)) {
                EXPECT_EQ(*result, wanted) << host << ", " << bypass << ' ' << phase;
            }
        }
        KillswitchEnv m_env;
    };
}

#endif
