#ifndef HEALTH_STATE_H
#define HEALTH_STATE_H

#include <functional>

namespace libxtun::health {

enum class ConnectionState { Unknown, Connected, NoNetwork, Disconnected };

class HealthListener {
  public:
    virtual ~HealthListener() = default;

    virtual void onConnectionState(ConnectionState state) noexcept = 0;
};

using LogSink = std::function<void(const char *)>;

}

#endif // HEALTH_STATE_H
