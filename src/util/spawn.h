#ifndef LIBXTUN_UTIL_SPAWN_H
#define LIBXTUN_UTIL_SPAWN_H

#include "util/noncopyable.h"
#include "util/result.h"

#include <spawn.h>

#include <string>
#include <vector>

namespace libxtun
{
    class SpawnActions final : private NonCopyable
    {
    public:
        SpawnActions() noexcept : m_valid(::posix_spawn_file_actions_init(&m_actions) == 0)
        {
        }
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
        [[nodiscard]] const posix_spawn_file_actions_t *get() const noexcept
        {
            return &m_actions;
        }

    private:
        posix_spawn_file_actions_t m_actions {};
        bool m_valid = false;
    };

    namespace spawn
    {
        ResultXtun<std::string> run(const char *binary, const std::vector<std::string> &args, const std::string &input);
    }
}

#endif
