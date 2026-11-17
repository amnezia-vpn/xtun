#ifndef TEST_KILLSWITCH_ENV_H
#define TEST_KILLSWITCH_ENV_H

#include "killswitch.h"
#include "path_probe.h"
#include "util/noncopyable.h"
#include "xtun.h"

#if !defined(_WIN32)
    #include <ifaddrs.h>
#endif

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"

namespace libxtun::test
{
    constexpr const char *LOOPBACK_V4 = "127.0.0.1";

#if !defined(_WIN32)
    inline std::string ifnameFromAddr(const char *address)
    {
        in_addr wanted {};
        ::ifaddrs *list = nullptr;
        if (::inet_pton(AF_INET, address, &wanted) != 1 || ::getifaddrs(&list) != 0) {
            return {};
        }

        std::string name;
        for (const ::ifaddrs *it = list; it != nullptr; it = it->ifa_next) {
            if (it->ifa_addr != nullptr && it->ifa_addr->sa_family == AF_INET
                && reinterpret_cast<const sockaddr_in *>(it->ifa_addr)->sin_addr.s_addr == wanted.s_addr) {
                name = it->ifa_name;
                break;
            }
        }
        ::freeifaddrs(list);
        return name;
    }
#endif

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
        [[nodiscard]] libxtun_error update(Killswitch &killswitch) const;
        [[nodiscard]] int ruleCount() const;
        [[nodiscard]] bool removeTunnelRoutes(const std::vector<std::string> &routes) const;

    private:
        std::string m_skipReason;
        int m_ifIndex = 0;
        std::string m_ifName;
    };

    class KillswitchTest : public ProbeTest
    {
    protected:
        void SetUp() override
        {
            ProbeTest::SetUp();
            if (IsSkipped() || HasFatalFailure()) {
                return;
            }
            if (!m_env.skipReason().empty()) {
                GTEST_SKIP() << "skipped: " << m_env.skipReason();
            }
        }
        [[nodiscard]] static bool persistent(libxtun_killswitch_mode mode) noexcept
        {
            return mode == LIBXTUN_KILLSWITCH_MODE_HARD;
        }
        KillswitchEnv m_env;
    };
}

#endif
