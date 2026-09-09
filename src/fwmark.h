#ifndef FWMARK_H
#define FWMARK_H

namespace libxtun
{
    constexpr unsigned int PROXY_FWMARK = 0x7874;
    constexpr unsigned int PROXY_TABLE = 0x7874;
    constexpr unsigned int KILLSWITCH_TABLE = 0x7875;

    constexpr unsigned int RULE_PRIORITY_KILLSWITCH_LAN = 32762;
    constexpr unsigned int RULE_PRIORITY_LAN = 32763;
    constexpr unsigned int RULE_PRIORITY_TUNNEL = 32764;
    constexpr unsigned int RULE_PRIORITY_KILLSWITCH_TUNNEL = 32765;
}

#endif // FWMARK_H
