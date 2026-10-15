#ifndef TEST_GUARANTEED_H
#define TEST_GUARANTEED_H

#include <optional>
#include <stdexcept>

namespace libxtun::test
{
    template<typename T> T guaranteed(std::optional<T> op)
    {
        if (!op) [[unlikely]] {
            throw std::runtime_error("optional does not have a value");
        }
        return std::move(*op);
    }
}

#endif
