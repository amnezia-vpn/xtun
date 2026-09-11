#ifndef LIBXTUN_UTIL_PIPE_H
#define LIBXTUN_UTIL_PIPE_H

#include "util/scoped_fd.h"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <optional>

namespace libxtun
{
    class Pipe final
    {
    public:
        static std::optional<Pipe> create() noexcept
        {
            std::array<int, 2> fds { -1, -1 };
            if (::pipe(fds.data()) != 0) {
                return std::nullopt;
            }
            Pipe pipe(fds);
            if (::fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0 || ::fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0) {
                return std::nullopt;
            }

            return pipe;
        }

        ScopedFd readFd;
        ScopedFd writeFd;

    private:
        explicit Pipe(std::array<int, 2> fds) noexcept : readFd(fds[0]), writeFd(fds[1])
        {
        }
    };
}

#endif
