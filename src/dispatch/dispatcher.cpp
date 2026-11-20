#include "dispatcher.h"
#include "dispatch/ip_classifier.h"
#include "io/injection_io.h"
#include "net/ip.h"
#include "proxy.h"
#include "tunnel_io.h"
#include <algorithm>
#include <memory>
#include <mutex>
#include <ranges>
#include <span>
#include <thread>
#include <utility>

namespace libxtun::dispatch
{
    Dispatcher::Dispatcher(TunnelIo &io) : m_io(io)
    {
        m_classifiers.push_back(std::make_unique<IpClassifier>());
    }

    Dispatcher::~Dispatcher()
    {
        std::unique_lock lock(m_mutex);
        downLocked();
    }

    bool Dispatcher::attach(Proxy *proxy)
    {
        std::unique_lock lock(m_mutex);
        Entry entry {
            .io = std::make_unique<InjectionIo>(m_io),
            .priority = m_nextPriority++,
        };
        auto res = m_iomap.emplace(proxy, std::move(entry));
        if (!res.second) {
            return false;
        }
        const auto &inserted = res.first->second;
        const auto profile = proxy->profile();

        proxy->attachIo(inserted.io.get());
        {
            std::unique_lock table(m_tableMutex);
            for (auto &classifier : m_classifiers) {
                classifier->set(inserted.io.get(), profile, inserted.priority);
            }
        }
        proxy->event(m_pump.joinable() ? ProxyEvent::Up : ProxyEvent::Down);
        return true;
    }

    bool Dispatcher::detach(Proxy *proxy)
    {
        std::unique_lock lock(m_mutex);
        auto removed = m_iomap.extract(proxy);
        if (removed.empty()) {
            return false;
        }
        teardown(removed.key(), removed.mapped());
        return true;
    }

    void Dispatcher::clear()
    {
        std::unique_lock lock(m_mutex);
        auto old = std::exchange(m_iomap, {});
        for (auto &[proxy, entry] : old) {
            teardown(proxy, entry);
        }
    }

    bool Dispatcher::empty() const
    {
        std::unique_lock lock(m_mutex);
        return m_iomap.empty();
    }

    void Dispatcher::teardown(Proxy *proxy, IoMap::mapped_type &entry)
    {
        {
            std::unique_lock table(m_tableMutex);
            for (auto &classifier : m_classifiers) {
                classifier->del(entry.io.get());
            }
        }
        proxy->event(ProxyEvent::Down);
        proxy->attachIo(nullptr);
    }

    void Dispatcher::event(ProxyEvent ev)
    {
        std::unique_lock lock(m_mutex);

        switch (ev) {
        case ProxyEvent::Up: upLocked(); break;
        case ProxyEvent::Down: downLocked(); break;
        case ProxyEvent::MtuUpdate: m_io.wake(); break;
        }

        for (const auto &proxy : m_iomap | std::views::keys) {
            proxy->event(ev);
        }
    }

    ProxyProfile Dispatcher::profile() const
    {
        std::unique_lock lock(m_mutex);

        using Item = decltype(m_iomap)::value_type;
        std::vector<const Item *> items;
        items.reserve(m_iomap.size());
        for (const auto &kv : m_iomap) {
            items.push_back(&kv);
        }
        std::ranges::sort(items, {}, [](const auto *kv) { return kv->second.priority; });

        std::vector<ProxyProfile> profiles;
        profiles.reserve(items.size());
        for (const auto &proxy : items | std::views::transform(&Item::first)) {
            profiles.emplace_back(proxy->profile());
        }

        ProxyProfile merged;
        for (const auto &profile : profiles) {
            if (profile.mtu != 0 && (merged.mtu == 0 || profile.mtu < merged.mtu)) {
                merged.mtu = profile.mtu;
            }
            for (const auto &server : profile.dnsServers) {
                if (std::ranges::all_of(merged.dnsServers, [&](const net::IpAddress &addr) { return addr != server; })) {
                    merged.dnsServers.push_back(server);
                }
            }
            for (const auto &include : profile.routes) {
                const bool known = std::ranges::any_of(merged.routes, [&](const net::IpPrefix &prefix) {
                    return prefix.bits() == include.bits() && prefix.address() == include.address();
                });
                if (!known) {
                    merged.routes.push_back(include);
                }
            }
            for (const auto &exclude : profile.excludes) {
                // the logic below as written:
                // throw away any excludes, that are fully covered by any of other's include route
                // this will not cover any cases of ~bad~ partial overlaps, like
                //      A wants to exclude 192.0.0.0/16
                //      B wants to include 192.0.0.0/24
                //
                // and it looks like the situation is unresolvable without subnets calculations,
                // which is bad as a general idea - it will end up with a LOT of extra subnets
                // being generated.
                //
                // the only idiomatic way to fix it without any workarounds is to assign subnet
                // wider than /32, with specific addresses assigned to specific Proxy instances
                // and making a routing around it. so:
                // TODO(cd-amn): make per-proxy routing to specific subnets
                const bool wanted = std::ranges::any_of(profiles, [&](const ProxyProfile &other) {
                    return &other != &profile && std::ranges::any_of(other.routes, [&](const net::IpPrefix &include) {
                        return include.bits() <= exclude.bits() && include.contains(exclude.address());
                    });
                });
                const bool known = std::ranges::any_of(merged.excludes, [&](const net::IpPrefix &prefix) {
                    return prefix.bits() == exclude.bits() && prefix.address() == exclude.address();
                });
                if (!known && !wanted) {
                    merged.excludes.push_back(exclude);
                }
            }
        }
        return merged;
    }

    void Dispatcher::upLocked()
    {
        downLocked();
        m_stop = false;
        m_pump = std::thread(&Dispatcher::pump, this);
    }

    void Dispatcher::downLocked()
    {
        if (!m_pump.joinable()) {
            return;
        }
        m_stop = true;
        m_io.wake();
        m_pump.join();
    }

    InjectionIo *Dispatcher::pickIo(std::span<const std::byte> pkt) const
    {
        for (const auto &classifier : m_classifiers) {
            if (auto *io = classifier->classify(pkt)) {
                return io;
            }
        }
        return nullptr;
    }

    void Dispatcher::pump() const
    {
        std::vector<std::byte> buf;

        while (!m_stop) {
            const int mtu = m_io.mtu();
            buf.resize(mtu > 0 ? mtu : 1500);
            while (!m_stop) {
                int n = m_io.read(buf);
                if (n < 0) {
                    return;
                }
                if (n == READ_WAKE) {
                    break;
                }
                auto pkt = std::span(buf).first(n);
                std::unique_lock table(m_tableMutex);
                if (const auto io = pickIo(pkt)) {
                    io->inject(pkt);
                }
            }
        }
    }
}
