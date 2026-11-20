#ifndef IP_CLASSIFIER_H
#define IP_CLASSIFIER_H

#include "classifier.h"
#include "io/injection_io.h"
#include "util/prefix_trie.h"

namespace libxtun::dispatch
{
    class IpClassifier : public Classifier
    {
    public:
        void set(InjectionIo *io, const ProxyProfile &profile, std::uint64_t priority) override;
        void del(InjectionIo *io) override;
        InjectionIo *classify(std::span<const std::byte> pkt) const override;

    private:
        struct Entry
        {
            InjectionIo *io = nullptr;
            std::uint64_t priority = 0;

            bool operator==(const Entry &other) const
            {
                return io == other.io;
            }
            bool operator<(const Entry &other) const
            {
                return priority < other.priority;
            }
        };

        util::PrefixTrie<Entry> m_includeTrie;
        util::PrefixTrie<Entry> m_excludeTrie;
    };
}

#endif // IP_CLASSIFIER
