#ifndef DISPATCH_CLASSIFIER_H
#define DISPATCH_CLASSIFIER_H

#include "io/injection_io.h"
#include "proxy.h"
#include <cstddef>
#include <cstdint>
#include <span>

namespace libxtun::dispatch
{
    class Classifier
    {
    public:
        virtual ~Classifier() = default;

        virtual void set(InjectionIo *io, const ProxyProfile &profile, std::uint64_t priority) = 0;
        virtual void del(InjectionIo *io) = 0;
        virtual InjectionIo *classify(std::span<const std::byte> pkt) const = 0;
    };
}

#endif // DISPATCH_CLASSIFIER_H
