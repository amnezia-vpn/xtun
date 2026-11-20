#ifndef UTIL_PREFIX_TRIE_H
#define UTIL_PREFIX_TRIE_H

#include "net/ip.h"
#include <algorithm>
#include <functional>
#include <memory>
#include <vector>
#include <span>

namespace libxtun::util
{
    template<typename T> class PrefixTrie
    {
    public:
        void insert(const net::IpPrefix &prefix, T value)
        {
            Node *node = &root(prefix.address().family());
            const auto octets = prefix.address().octets();

            for (unsigned i = 0; i < prefix.bits(); i++) {
                auto &child = node->child[bitAt(octets, i)];
                if (!child) {
                    child = std::make_unique<Node>();
                }
                node = child.get();
            }
            auto &values = node->values;
            values.insert(std::ranges::upper_bound(values, value, std::less {}), std::move(value));
        }

        void erase(const T &value)
        {
            prune(m_v4, value);
            prune(m_v6, value);
        }

        template<typename F> T match(const net::IpAddress &addr, F &&validate) const
        {
            T best {};
            const auto octets = addr.octets();
            const auto maxBits = octets.size() * 8;
            const Node *node = &root(addr.family());
            unsigned i = 0;

            while (node) {
                const auto found = std::ranges::find_if(node->values, validate);
                if (found != node->values.end()) {
                    best = *found;
                }
                node = i < maxBits ? node->child[bitAt(octets, i++)].get() : nullptr;
            }
            return best;
        }

    private:
        struct Node
        {
            std::unique_ptr<Node> child[2];
            std::vector<T> values;
        };

        static unsigned bitAt(std::span<const std::byte> octets, unsigned i)
        {
            return (static_cast<unsigned>(octets[i / 8]) >> (7 - i % 8)) & 1U;
        }
        Node &root(int family)
        {
            return family == AF_INET ? m_v4 : m_v6;
        }
        const Node &root(int family) const
        {
            return family == AF_INET ? m_v4 : m_v6;
        }
        static bool prune(Node &node, const T &value)
        {
            std::erase(node.values, value);
            for (auto &child : node.child) {
                if (child && prune(*child, value)) {
                    child.reset();
                }
            }
            return node.values.empty() && !node.child[0] && !node.child[1];
        }

        Node m_v4, m_v6;
    };

}

#endif // UTIL_PREFIX_TRIE_H
