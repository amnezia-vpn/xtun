#ifndef FWMARK_H
#define FWMARK_H

namespace libxtun
{
    constexpr unsigned int PROXY_FWMARK = 0x7874;
    constexpr unsigned int PROXY_TABLE = 0x7874;

    constexpr unsigned int RULE_PRIORITY_LAN = 32763;
    constexpr unsigned int RULE_PRIORITY_TUNNEL = 32764;
}

#endif // FWMARK_H
