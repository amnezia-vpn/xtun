#ifndef LIBXTUN_UTIL_SCOPED_FD_H
#define LIBXTUN_UTIL_SCOPED_FD_H

#include "util/noncopyable.h"

#include <unistd.h>

#include <utility>

namespace libxtun
{
    class ScopedFd final : private NonCopyable
    {
    public:
        explicit ScopedFd(int fd) noexcept : m_fd(fd)
        {
        }
        ScopedFd(ScopedFd &&other) noexcept : m_fd(std::exchange(other.m_fd, -1))
        {
        }
        ~ScopedFd()
        {
            close();
        }

        [[nodiscard]] int get() const noexcept
        {
            return m_fd;
        }
        void close() noexcept
        {
            if (m_fd >= 0) {
                ::close(std::exchange(m_fd, -1));
            }
        }

    private:
        int m_fd = -1;
    };
}

#endif
