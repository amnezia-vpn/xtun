#include "proxy.h"
#include "xtun.h"

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#ifndef TUNNEL_H
#define TUNNEL_H

namespace libxtun {


class Tunnel {
  public:
    enum class Event { Up, Down, MtuUpdate };

    Tunnel(const libxtun_tunnel_opts &opts);
    ~Tunnel();

    int openTun();

    int read(void *buf, size_t len);
    int write(const void *buf, size_t len);

    int mtu() const;
    const std::string &name() const { return m_name; }

    bool up() const { return m_up; }
    int currentMtu() const { return m_mtu; }
    void onEvent(std::function<void(Event)> cb) { m_onEvent = std::move(cb); }

    void attachProxy(Proxy &&proxy);

  private:
    void startMonitor();
    void stopMonitor();
    void monitorLoop();

    std::vector<std::string> m_dns;
    std::vector<std::string> m_dnsExceptions;
    libxtun_killswitch_mode m_killswitchMode;

    int m_tunFd;
    std::string m_name;
    int m_ifIndex;

    int m_netlinkFd;
    int m_cancelFd;
    std::thread m_monitor;
    std::atomic<bool> m_up;
    std::atomic<int> m_mtu;
    std::function<void(Event)> m_onEvent;
};


}

#endif // TUNNEL_H
