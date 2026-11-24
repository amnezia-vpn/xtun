#ifndef CINTEROP_H
#define CINTEROP_H

#include "util/result.h"
#include "xtun.h"
#include <cstring>
#include <string>
#include <vector>

namespace libxtun::cinterop
{
    template<typename T> ResultXtun<std::vector<T>> inline parseListT(const char *const *list)
    {
        std::vector<T> out;
        if (list == nullptr) {
            return out;
        }
        while (*list != nullptr) {
            auto res = T::parse(*list);
            if (!res) {
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }
            out.emplace_back(std::move(*res));
            ++list;
        }
        return out;
    }

    template<typename T> ResultXtun<T> inline readSized(const T &opts)
    {
        if (opts.size > sizeof(T)) {
            return fail(LIBXTUN_ERR_UNSUPPORTED);
        }
        T out {};
        std::memcpy(&out, &opts, opts.size);
        return out;
    }

    std::vector<std::string> inline parseStrList(const char *const *list)
    {
        std::vector<std::string> out;
        if (list == nullptr) {
            return out;
        }
        while (*list != nullptr) {
            out.push_back(*list);
            ++list;
        }
        return out;
    }

    struct StrList
    {
        std::vector<std::string> strs;
        std::vector<const char *> ptrs;

        StrList() = default;
        StrList(StrList &&) = default;
        StrList &operator=(StrList &&) = default;
        StrList(const StrList &) = delete;
        StrList &operator=(const StrList &) = delete;

        const char *const *data() const
        {
            return ptrs.data();
        }
    };

    template<typename T> StrList toStrList(const std::vector<T> &list)
    {
        StrList out;
        out.strs.reserve(list.size());
        out.ptrs.reserve(list.size() + 1);
        for (const auto &item : list) {
            out.ptrs.push_back(out.strs.emplace_back(item.toString()).c_str());
        }
        out.ptrs.push_back(nullptr);
        return out;
    }
}

#endif
