#ifndef RESULT_H
#define RESULT_H

#include "xtun.h"

#include <utility>
#include <variant>

namespace libxtun
{

    template<typename E> struct Failure
    {
        E error;
    };

    template<typename E> Failure<std::decay_t<E>> fail(E &&e)
    {
        return Failure<std::decay_t<E>> { std::forward<E>(e) };
    }

    template<typename T, typename E> class ResultGeneric
    {
    public:
        ResultGeneric(T res) : m_res(std::in_place_index<0>, std::move(res))
        {
        }

        template<typename U> ResultGeneric(Failure<U> f) : m_res(std::in_place_index<1>, std::move(f.error))
        {
        }

        template<typename U, typename = std::enable_if_t<std::is_convertible_v<U, T> && !std::is_same_v<U, T>>>
        ResultGeneric(ResultGeneric<U, E> &&other)
        {
            if (other.has_value())
                m_res.template emplace<0>(std::move(other).value());
            else
                m_res.template emplace<1>(std::move(other).error());
        }

        static ResultGeneric fail(E e)
        {
            return ResultGeneric(std::in_place_index<1>, std::move(e));
        }

        inline bool has_value() const noexcept
        {
            return m_res.index() == 0;
        }

        explicit inline operator bool() const noexcept
        {
            return has_value();
        }

        T &value() &
        {
            return std::get<0>(m_res);
        }
        const T &value() const &
        {
            return std::get<0>(m_res);
        }
        T &&value() &&
        {
            return std::get<0>(std::move(m_res));
        }

        E &error() &
        {
            return std::get<1>(m_res);
        }
        const E &error() const &
        {
            return std::get<1>(m_res);
        }
        E &&error() &&
        {
            return std::get<1>(std::move(m_res));
        }

        template<typename, typename> friend class ResultGeneric;

    private:
        template<class... Args> explicit ResultGeneric(std::in_place_index_t<1> tag, Args &&...args)
            : m_res(tag, std::forward<Args>(args)...)
        {
        }

        std::variant<T, E> m_res;
    };

    template<typename T> using ResultXtun = ResultGeneric<T, enum libxtun_error>;

}

#endif
