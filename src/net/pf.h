#ifndef LIBXTUN_NET_PF_H
#define LIBXTUN_NET_PF_H
#include "util/result.h"
#include "xtun.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace libxtun::pf
{
    constexpr const char *BINARY = "/sbin/pfctl";
    constexpr const char *ANCHOR_REF = "com.apple/*";
    constexpr std::string_view TOKEN_MARKER = "Token :";

    ResultXtun<std::string> pfctl(const std::vector<std::string> &args, const std::string &input);
    libxtun_error loadRules(const std::string &rules, const std::string &anchor);
    libxtun_error flushRules(const std::string &anchor);
    libxtun_error enable(std::uint64_t &token);
    libxtun_error disable(std::uint64_t token);
}
#endif
