#ifndef LIBXTUN_NET_WFP_H
#define LIBXTUN_NET_WFP_H

#include "util/noncopyable.h"
#include "util/result.h"
#include "xtun.h"

#include <fwptypes.h>
#include <fwpmu.h>
#include <windows.h>

#include <memory>
#include <vector>

namespace libxtun::wfp
{
    struct WfpConfig {
        GUID provider;
        const wchar_t *providerName;
        const wchar_t *providerDesc;
        GUID sublayer;
        const wchar_t *sublayerName;
        const wchar_t *sublayerDesc;
        UINT16 sublayerWeight;
        bool persistent;
    };

    struct FilterInfo
    {
        UINT64 id;
        GUID layer;
        FWP_ACTION_TYPE action;
    };

    struct FwpmMemoryDeleter
    {
        void operator()(void *memory) const noexcept
        {
            ::FwpmFreeMemory(&memory);
        }
    };

    class WfpEngine final : private NonCopyable
    {
    public:
        ~WfpEngine();

        class Transaction final : private NonCopyable
        {
        public:
            explicit Transaction(WfpEngine &engine) noexcept;
            ~Transaction();

            [[nodiscard]] libxtun_error status() const noexcept { return m_status; }
            libxtun_error commit() noexcept;

        private:
            HANDLE m_engine = nullptr;
            libxtun_error m_status = LIBXTUN_OK;
        };

        static ResultXtun<std::unique_ptr<WfpEngine>> open(WfpConfig config);

        libxtun_error addProvider() noexcept;
        libxtun_error addSublayer() noexcept;
        libxtun_error addFilter(const GUID &layer, const FWP_ACTION_TYPE action, FWPM_FILTER_CONDITION *condition, const wchar_t *name) noexcept;
        ResultXtun<std::vector<FilterInfo>> getInstalledFilters();
        libxtun_error deleteFilters();
        libxtun_error cleanup();

    private:
        explicit WfpEngine(const WfpConfig config) : m_config(config) {}

        HANDLE m_engine = nullptr;
        WfpConfig m_config;
    };
}
#endif
