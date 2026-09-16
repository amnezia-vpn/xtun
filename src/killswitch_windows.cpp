#include "killswitch_windows.h"
#include "xtun.h"
#include "net/wfp.h"

#include <ifdef.h>
#include <netioapi.h>
#include <winerror.h>

#include <array>
#include <string>

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

        auto engine = wfp::WfpEngine::open(makeWfpConfig(persistent()));
        if (!engine) {
            return engine.error();
        }

        m_wfp = std::move(engine).value();

        if (const auto result = installFilters(luid.Value); result != LIBXTUN_OK) {
            m_wfp.reset();
            return result;
        }

        return LIBXTUN_OK;
    }

    void WindowsKillswitch::remove() noexcept
    {
        if (m_wfp != nullptr) {
            m_wfp->cleanup();
            m_wfp.reset();
            return;
        }

        auto engine = wfp::WfpEngine::open(makeWfpConfig(false));
        if (engine) {
            engine.value()->cleanup();
        }
    }

    libxtun_error WindowsKillswitch::installFilters(std::uint64_t luidValue) noexcept
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

        for (const auto layer: { FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6 }) {
            if (auto result = blockAll(layer); result != LIBXTUN_OK) {
                return result;
            }
            if (auto result = allowTunnel(layer, luidValue); result != LIBXTUN_OK) {
                return result;
            }
            if (auto result = allowLoopback(layer); result != LIBXTUN_OK) {
                return result;
            }
            if (auto result = allowAppTraffic(layer); result != LIBXTUN_OK) {
                return result;
            }
        }

        return transaction.commit();
    }

    libxtun_error WindowsKillswitch::blockAll(const GUID &layer) noexcept
    {
        return m_wfp->addFilter(layer, FWP_ACTION_BLOCK, nullptr, L"Block internet traffic");
    }

    libxtun_error WindowsKillswitch::allowTunnel(const GUID &layer, std::uint64_t luidValue) noexcept
    {
        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT64;
        condition.conditionValue.uint64 = &luidValue;

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, &condition, L"Allow traffic via tunnel");
    }

    libxtun_error WindowsKillswitch::allowLoopback(const GUID &layer) noexcept
    {
        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = FWPM_CONDITION_FLAGS;
        condition.matchType = FWP_MATCH_FLAGS_ANY_SET;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, &condition, L"Allow loopback traffic");
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

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, &condition, L"Allow app traffic");
    }
}
