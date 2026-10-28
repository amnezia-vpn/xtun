#ifndef LIBXTUN_UTIL_PROCESS_H
#define LIBXTUN_UTIL_PROCESS_H

#include "util/result.h"

#include <string>
#include <vector>

namespace libxtun
{
    namespace process
    {
        ResultXtun<int> run(const char *binary, const std::vector<std::string> &args);
    }
}

#endif
