#include "iptables.h"
#include "util/spawn.h"
#include "xtun.h"

#include <sys/socket.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace libxtun::iptables
{
    namespace
    {
        std::string_view iptablesBin(int family) noexcept
        {
            return family == AF_INET6 ? "ip6tables" : "iptables";
        }

        std::string_view iptablesRestoreBin(int family) noexcept
        {
            return family == AF_INET6 ? "ip6tables-restore" : "iptables-restore";
        }

        std::optional<std::string> binaryPath(std::string_view name)
        {
            for (const std::string_view dir : { "/usr/sbin/", "/sbin/" }) {
                std::string path = std::string(dir).append(name);
                if (::access(path.c_str(), X_OK) == 0) {
                    return path;
                }
            }
            return std::nullopt;
        }

        ResultXtun<std::string> execute(std::string_view name, const std::vector<std::string> &args,
                                        const std::string &input = {})
        {
            const std::optional<std::string> path = binaryPath(name);
            if (!path) {
                return fail(LIBXTUN_ERR_SYSTEM);
            }
            return spawn::run(path->c_str(), args, input);
        }
    }

    libxtun_error run(int family, const std::vector<std::string> &args)
    {
        const auto result = execute(iptablesBin(family), args);
        return result ? LIBXTUN_OK : result.error();
    }

    libxtun_error restore(int family, const std::string &rules)
    {
        const auto result = execute(iptablesRestoreBin(family), { "--noflush" }, rules);
        return result ? LIBXTUN_OK : result.error();
    }

    ResultXtun<std::string> rules(int family, const std::string &table, const std::string &chain)
    {
        return execute(iptablesBin(family), { "-t", table, "-S", chain });
    }
}
