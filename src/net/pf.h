#ifndef LIBXTUN_NET_PF_H
#define LIBXTUN_NET_PF_H
#include "util/noncopyable.h"
#include "util/result.h"
#include "xtun.h"

#include <spawn.h>
#include <sys/wait.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace libxtun::pf
{
    constexpr const char *BINARY = "/sbin/pfctl";
    constexpr const char *ANCHOR_REF = "com.apple/*";
    constexpr std::string_view TOKEN_MARKER = "Token :";

    class SpawnActions final : private NonCopyable
    {
    public:
        SpawnActions() noexcept : m_valid(::posix_spawn_file_actions_init(&m_actions) == 0) {}
        ~SpawnActions()
        {
            if (m_valid) {
                ::posix_spawn_file_actions_destroy(&m_actions);
            }
        }

        [[nodiscard]] bool dup2(int fd, int target) noexcept
        {
            return m_valid && ::posix_spawn_file_actions_adddup2(&m_actions, fd, target) == 0;
        }
        [[nodiscard]] const posix_spawn_file_actions_t *get() const noexcept { return &m_actions; }

    private:
        posix_spawn_file_actions_t m_actions {};
        bool m_valid = false;
    };

    ResultXtun<std::string> pfctl(const std::vector<std::string> &args, const std::string &input);
    libxtun_error loadRules(const std::string &rules, const std::string &anchor);
    libxtun_error flushRules(const std::string &anchor);
    libxtun_error enable(std::uint64_t &token);
    libxtun_error disable(std::uint64_t token);
}
#endif
