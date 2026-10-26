#include "killswitch_windows.h"
#include "xtun.h"
#include "net/wfp.h"

#include <ifdef.h>
#include <netioapi.h>
#include <winerror.h>

#include <array>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace libxtun
{
    wfp::WfpConfig makeWfpConfig(bool persistent) noexcept {
        wfp::WfpConfig config {};
        config.provider = PROVIDER_KEY;
        config.providerName = L"xtun-killswitch-provider";
        config.providerDesc = L"xtun Killswitch Provider";
        config.sublayer = SUBLAYER_KEY;
        config.sublayerName = L"xtun-killswitch-sublayer";
        config.sublayerDesc = L"xtun Killswitch Sublayer";
        config.sublayerWeight = SUBLAYER_WEIGHT;
        config.persistent = persistent;
        return config;
    }

    libxtun_error WindowsKillswitch::install(int ifIndex, const std::string &ifName)
    {
        (void)ifName;

        NET_LUID luid {};
        if (ifIndex <= 0 || ::ConvertInterfaceIndexToLuid(static_cast<NET_IFINDEX>(ifIndex), &luid) != NO_ERROR) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        // filters installed by HARD mode cannot be removed from dynamic WFP session used by SOFT
        // thus, we have to use an engine with different config
        if (!persistent()) {
            auto leftovers = wfp::WfpEngine::open(makeWfpConfig(true));
            if (!leftovers) {
                return leftovers.error();
            }
            if (const auto result = leftovers.value()->cleanup(); result != LIBXTUN_OK) {
                return result;
            }
        }

        auto engine = wfp::WfpEngine::open(makeWfpConfig(persistent()));
        if (!engine) {
            return engine.error();
        }

        m_wfp = std::move(engine).value();
        m_luid = luid.Value;

        if (const auto result = installFilters(m_luid, protectedSet({})); result != LIBXTUN_OK) {
            m_wfp.reset();
            return result;
        }

        return LIBXTUN_OK;
    }

    libxtun_error WindowsKillswitch::setProtected(const std::vector<net::IpPrefix> &prefixes)
    {
        return installFilters(m_luid, prefixes);
    }

    void WindowsKillswitch::remove() noexcept
    {
        if (m_wfp != nullptr) {
            m_wfp->cleanup();
            m_wfp.reset();
            return;
        }

        auto engine = wfp::WfpEngine::open(makeWfpConfig(true));
        if (engine) {
            engine.value()->cleanup();
        }
    }

    libxtun_error WindowsKillswitch::installFilters(std::uint64_t luidValue, const std::vector<net::IpPrefix> &prefixes)
    {
        wfp::WfpEngine::Transaction transaction(*m_wfp);
        if (transaction.status() != LIBXTUN_OK) {
            return transaction.status();
        }

        // cleanup any leftover filters possibly installed in HARD mode before installing new ones
        // do it in one transaction to ensure no window without killswitch exists
        if (const auto result = m_wfp->deleteFilters(); result != LIBXTUN_OK) {
            return result;
        }

        if (const auto result = m_wfp->addProvider(); result != LIBXTUN_OK) {
            return result;
        }

        if (const auto result = m_wfp->addSublayer(); result != LIBXTUN_OK) {
            return result;
        }

        struct FamilyLayers
        {
            int family;
            GUID connect;
            GUID recvAccept;
        };
        const std::array<FamilyLayers, 2> families { {
            { AF_INET, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
            { AF_INET6, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 },
        } };
        for (const FamilyLayers &layers : families) {
            for (const GUID &layer : { layers.connect, layers.recvAccept }) {
                if (auto result = allowTunnel(layer, FWPM_CONDITION_IP_LOCAL_INTERFACE, luidValue);
                    result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = allowLoopback(layer); result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = allowAppTraffic(layer); result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = blockProtected(layer, FWPM_CONDITION_IP_REMOTE_ADDRESS, layers.family, prefixes);
                    result != LIBXTUN_OK) {
                    return result;
                }
            }
        }

        return transaction.commit();
    }

    libxtun_error WindowsKillswitch::blockProtected(const GUID &layer, const GUID &field, int family,
                                                    const std::vector<net::IpPrefix> &prefixes)
    {
        const auto v4AddrMask = [](const net::IpPrefix &prefix) {
            ULONG mask = 0;
            ::ConvertLengthToIpv4Mask(prefix.bits(), &mask);
            std::uint32_t address = 0;
            std::memcpy(&address, prefix.address().octets().data(), sizeof(address));
            return FWP_V4_ADDR_AND_MASK { ::ntohl(address), ::ntohl(mask) };
        };
        const auto v6AddrMask = [](const net::IpPrefix &prefix) {
            FWP_V6_ADDR_AND_MASK addrMask {};
            std::memcpy(addrMask.addr, prefix.address().octets().data(), sizeof(addrMask.addr));
            addrMask.prefixLength = static_cast<UINT8>(prefix.bits());
            return addrMask;
        };

        std::vector<FWP_V4_ADDR_AND_MASK> v4AddrMasks;
        std::vector<FWP_V6_ADDR_AND_MASK> v6AddrMasks;
        v4AddrMasks.reserve(prefixes.size());
        v6AddrMasks.reserve(prefixes.size());

        std::vector<FWPM_FILTER_CONDITION> conditions;
        for (const net::IpPrefix &prefix : prefixes) {
            if (prefix.address().family() != family) {
                continue;
            }
            if (prefix.isDefaultRoute()) {
                return m_wfp->addFilter(layer, FWP_ACTION_BLOCK, {}, L"Block traffic to protected destinations");
            }

            FWPM_FILTER_CONDITION condition {};
            condition.fieldKey = field;
            condition.matchType = FWP_MATCH_EQUAL;
            if (family == AF_INET) {
                condition.conditionValue.type = FWP_V4_ADDR_MASK;
                condition.conditionValue.v4AddrMask = &v4AddrMasks.emplace_back(v4AddrMask(prefix));
            } else {
                condition.conditionValue.type = FWP_V6_ADDR_MASK;
                condition.conditionValue.v6AddrMask = &v6AddrMasks.emplace_back(v6AddrMask(prefix));
            }
            conditions.push_back(condition);
        }

        if (conditions.empty()) {
            return LIBXTUN_OK;
        }
        return m_wfp->addFilter(layer, FWP_ACTION_BLOCK, conditions, L"Block traffic to protected destinations");
    }

    libxtun_error WindowsKillswitch::allowTunnel(const GUID &layer, const GUID &field, std::uint64_t luidValue) noexcept
    {
        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = field;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT64;
        condition.conditionValue.uint64 = &luidValue;

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, std::span(&condition, 1), L"Allow traffic via tunnel");
    }

    libxtun_error WindowsKillswitch::allowLoopback(const GUID &layer) noexcept
    {
        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = FWPM_CONDITION_FLAGS;
        condition.matchType = FWP_MATCH_FLAGS_ANY_SET;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, std::span(&condition, 1), L"Allow loopback traffic");
    }

    libxtun_error WindowsKillswitch::allowAppTraffic(const GUID &layer) noexcept
    {
        std::array<wchar_t, MAX_PATH> path {};
        if (::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())) == 0)
        {
            return LIBXTUN_ERR_SYSTEM;
        }

        FWP_BYTE_BLOB *rawAppId = nullptr;
        if (::FwpmGetAppIdFromFileName(path.data(), &rawAppId) != ERROR_SUCCESS) {
            return LIBXTUN_ERR_SYSTEM;
        }
        const std::unique_ptr<FWP_BYTE_BLOB, wfp::FwpmMemoryDeleter> appId(rawAppId);

        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.byteBlob = appId.get();

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, std::span(&condition, 1), L"Allow app traffic");
    }
}
