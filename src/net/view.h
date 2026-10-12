#ifndef VIEW_H
#define VIEW_H

#include <concepts>
#include <span>
#include <type_traits>

namespace libxtun::net
{
    template<typename T>
    concept BasicRef = std::same_as<std::remove_cv_t<decltype(T::HEADER_LEN)>, std::size_t>
            && std::integral_constant<std::size_t, T::HEADER_LEN>::value == T::HEADER_LEN
            && std::constructible_from<T, std::span<std::byte, T::HEADER_LEN>>;

    template<typename T>
    concept BasicView = BasicRef<T> && std::constructible_from<T, std::span<const std::byte, T::HEADER_LEN>>;
};

#endif
