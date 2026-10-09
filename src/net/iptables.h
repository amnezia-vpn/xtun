#ifndef LIBXTUN_NET_IPTABLES_H
#define LIBXTUN_NET_IPTABLES_H
#include "util/result.h"
#include "xtun.h"

#include <string>
#include <vector>

namespace libxtun::iptables
{
    libxtun_error run(int family, const std::vector<std::string> &args);
    libxtun_error restore(int family, const std::string &rules);
    ResultXtun<std::string> rules(int family, const std::string &table, const std::string &chain);
}
#endif
