#include "pf.h"
#include "xtun.h"
#include "util/pipe.h"
#include "util/result.h"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <vector>

namespace libxtun::pf
{
    ResultXtun<std::string> pfctl(const std::vector<std::string> &args, const std::string &input)
    {
        auto feed = Pipe::create();
        auto collect = Pipe::create();
        if (!feed || !collect) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        if (::fcntl(feed->writeFd.get(), F_SETNOSIGPIPE, 1) != 0) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        SpawnActions actions;
        if (!actions.dup2(feed->readFd.get(), STDIN_FILENO)
            || !actions.dup2(collect->writeFd.get(), STDOUT_FILENO)
            || !actions.dup2(collect->writeFd.get(), STDERR_FILENO)) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        std::vector<char *> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(const_cast<char *>(BINARY));
        for (const std::string &arg : args) {
            argv.push_back(const_cast<char *>(arg.c_str()));
        }
        argv.push_back(nullptr);

        pid_t child = -1;
        std::array<char *, 1> env = { nullptr };
        if (::posix_spawn(&child, BINARY, actions.get(), nullptr, argv.data(), env.data())) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        feed->readFd.close();
        collect->writeFd.close();

        for (std::size_t sent = 0; sent < input.size();) {
            const ssize_t chunk = ::write(feed->writeFd.get(), input.data() + sent, input.size() - sent);
            if (chunk < 0) {
                break;
            }
            sent += static_cast<std::size_t>(chunk);
        }
        feed->writeFd.close();

        std::string output;
        std::array<char, 512> buffer {};
        ssize_t received = 0;
        while ((received = ::read(collect->readFd.get(), buffer.data(), buffer.size())) > 0) {
            output.append(buffer.data(), static_cast<std::size_t>(received));
        }

        int status = 0;
        if (::waitpid(child, &status, 0) < 0) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        return output;
    }

    libxtun_error loadRules(const std::string &rules, const std::string &anchor)
    {

        if (const auto result = pfctl({"-s", "rules"}, {}); !result) {
            return result.error();
        } else if (result.has_value() && (result.value().find(ANCHOR_REF) == std::string::npos)) {
            return LIBXTUN_ERR_SYSTEM;
        }
        const auto result = pfctl({ "-a", anchor, "-f", "-" }, rules);
        return result ? LIBXTUN_OK : result.error();
    }

    libxtun_error flushRules(const std::string &anchor)
    {
        const auto result = pfctl({ "-a", anchor, "-F", "all" }, {});
        return result ? LIBXTUN_OK : result.error();
    }

    libxtun_error enable(std::uint64_t &token)
    {
        const auto result = pfctl({ "-E" }, {});
        if (!result) {
            return result.error();
        }

        const std::string &output = result.value();
        const std::size_t marker = output.find(TOKEN_MARKER);

        if (marker == std::string::npos || (token = std::strtoull(output.c_str() + marker + TOKEN_MARKER.size(), nullptr, 10)) == 0) {
            (void)pfctl({ "-d" }, {});
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error disable(std::uint64_t token)
    {
        const auto result = pfctl({ "-X" , std::to_string(token) }, {});
        return result ? LIBXTUN_OK : result.error();
    }
}
