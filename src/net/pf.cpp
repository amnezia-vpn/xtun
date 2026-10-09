#include "pf.h"
#include "xtun.h"
#include "util/result.h"
#include "util/spawn.h"

#include <cstdlib>
#include <vector>

namespace libxtun::pf
{
    ResultXtun<std::string> pfctl(const std::vector<std::string> &args, const std::string &input)
    {
        return spawn::run(BINARY, args, input);
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
