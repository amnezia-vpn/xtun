#ifndef REFLECT_H
#define REFLECT_H

#include <optional>
#include <vector>

namespace libxtun {
namespace reflect {

template<typename M>
struct member_traits {
};
template<typename T, typename C>
struct member_traits<T C::*> {
    using owner = C;
    using slot = T;
};
template<auto T> using owner_t = typename member_traits<decltype(T)>::owner;
template<auto T> using slot_t = typename member_traits<decltype(T)>::slot;

template<typename T>
struct slot_traits {
    using field = T;
};
template<typename T>
struct slot_traits<std::optional<T>> {
    using field = T;
};
template<typename T>
struct slot_traits<std::vector<T>> {
    using field = T;
};
template<typename T> using field_t = typename slot_traits<T>::field;

template<std::size_t N>
struct fixed_string {
    char data[N]{};
    constexpr fixed_string(const char (&s)[N]) {
        for (std::size_t i = 0; i < N; ++i) data[i] = s[i];
    }
    static constexpr bool empty() {
        return N <= 1;
    }
};

template <typename T>
struct is_optional : std::false_type {
};
template <typename T>
struct is_optional<std::optional<T>> : std::true_type {
};
template <typename T>
inline constexpr bool is_optional_v = is_optional<T>::value;

template <typename T>
struct is_vector : std::false_type {
};
template <typename T>
struct is_vector<std::vector<T>> : std::true_type {
};
template <typename T>
inline constexpr bool is_vector_v = is_vector<T>::value;

}
}

#endif
