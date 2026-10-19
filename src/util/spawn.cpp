#include "spawn.h"
#include "util/pipe.h"
#include "util/result.h"
#include "xtun.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <vector>

namespace libxtun::spawn
{
    ResultXtun<std::string> run(const char *binary, const std::vector<std::string> &args, const std::string &input)
    {
        auto feed = Pipe::create();
        auto collect = Pipe::create();
        if (!feed || !collect) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        // input must fit the pipe buffer (64 KiB on Linux), raise it with F_SETPIPE_SZ for larger input
        if (::fcntl(feed->writeFd.get(), F_SETFL, O_NONBLOCK) != 0
            || ::write(feed->writeFd.get(), input.data(), input.size()) != static_cast<ssize_t>(input.size())) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        feed->writeFd.close();

        SpawnActions actions;
        if (!actions.dup2(feed->readFd.get(), STDIN_FILENO) || !actions.dup2(collect->writeFd.get(), STDOUT_FILENO)
            || !actions.dup2(collect->writeFd.get(), STDERR_FILENO)) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        std::vector<char *> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(const_cast<char *>(binary));
        for (const std::string &arg : args) {
            argv.push_back(const_cast<char *>(arg.c_str()));
        }
        argv.push_back(nullptr);

        pid_t child = -1;
        std::array<char *, 1> env = { nullptr };
        if (::posix_spawn(&child, binary, actions.get(), nullptr, argv.data(), env.data())) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        feed->readFd.close();
        collect->writeFd.close();

        std::string output;
        std::array<char, 512> buffer {};
        ssize_t received = 0;
        while ((received = ::read(collect->readFd.get(), buffer.data(), buffer.size())) > 0) {
            output.append(buffer.data(), static_cast<std::size_t>(received));
        }

        int status = 0;
        pid_t r;
        do {
            r = ::waitpid(child, &status, 0);
        } while (r == -1 && errno == EINTR);

        if (r < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        return output;
    }
}
