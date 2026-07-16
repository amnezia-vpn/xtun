#include "proxy.h"
#include "xtun.h"

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <wintun.h>
#endif

#ifndef TUNNEL_H
#define TUNNEL_H

namespace libxtun {


class Tunnel {
  public:
    enum class Event { Up, Down, MtuUpdate };

    Tunnel(const libxtun_tunnel_opts &opts);
    ~Tunnel();

    int openTun();
    int adoptTun(int fd);
    int adoptTunByName(const char *name);

    int read(void *buf, size_t len);
    int write(const void *buf, size_t len);

    int mtu() const;
    const std::string &name() const { return m_name; }

    bool up() const { return m_up; }
    int currentMtu() const { return m_mtu; }
    void onEvent(std::function<void(Event)> cb) { m_onEvent = std::move(cb); }

    int attachProxy(Proxy *proxy);

  private:
    friend class Proxy;

    void detachProxy(Proxy *proxy);
    void cancelRead();
    int finishOpen();
    void emit(Event ev);
#if defined(_WIN32)
    int loadWintun(WINTUN_CREATE_ADAPTER_FUNC *&createAdapter,
                   WINTUN_OPEN_ADAPTER_FUNC *&openAdapter,
                   WINTUN_START_SESSION_FUNC *&startSession,
                   WINTUN_GET_READ_WAIT_EVENT_FUNC *&getReadWaitEvent);
    int startWintunSession(WINTUN_START_SESSION_FUNC *startSession,
                           WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent);
#endif
    void startMonitor();
    void stopMonitor();
    void monitorLoop();

    std::vector<std::string> m_dns;
    std::vector<std::string> m_dnsExceptions;
    libxtun_killswitch_mode m_killswitchMode;

    int m_tunFd;
    std::string m_name;
    int m_ifIndex;

    int m_monitorFd;
    int m_cancelFd;
    int m_readCancelRd;
    int m_readCancelWr;
    std::thread m_monitor;
    std::atomic<bool> m_up;
    std::atomic<int> m_mtu;
    std::function<void(Event)> m_onEvent;
    Proxy *m_proxy = nullptr;

#if defined(_WIN32)
    HMODULE m_wintun = nullptr;
    WINTUN_ADAPTER_HANDLE m_adapter = nullptr;
    WINTUN_SESSION_HANDLE m_session = nullptr;
    HANDLE m_readWait = nullptr;
    std::atomic<bool> m_closing{false};
    std::atomic<int> m_running{0};
    int m_forcedMtu = 1420;

    WINTUN_CLOSE_ADAPTER_FUNC *m_closeAdapter = nullptr;
    WINTUN_END_SESSION_FUNC *m_endSession = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC *m_receivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *m_releaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *m_allocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC *m_sendPacket = nullptr;
#endif
};


}

#endif // TUNNEL_H
