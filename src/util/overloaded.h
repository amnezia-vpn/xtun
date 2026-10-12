#ifndef OVERLOADED_H
#define OVERLOADED_H

namespace libxtun
{
    template<class... F> struct overloaded : F...
    {
        using F::operator()...;
    };
}

#endif
