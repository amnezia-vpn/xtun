#include "killswitch.h"
#include "router.h"
#include "tun_device.h"

#if defined(_WIN32)
    #include "router_windows.cpp"
    #include "router_windows.h"
    #include "tun_device_windows.cpp"
    #include "tun_device_windows.h"
#elif defined(__APPLE__)
    #include "router_macos.cpp"
    #include "router_macos.h"
    #include "tun_device_macos.cpp"
    #include "tun_device_macos.h"
    #include "killswitch_macos.cpp"
    #include "killswitch_macos.h"
    #include "net/pf.cpp"
#elif defined(__ANDROID__)
    #include "tun_device_linux.cpp"
    #include "tun_device_linux.h"
#elif defined(__linux__)
    #include "router_linux.cpp"
    #include "router_linux.h"
    #include "tun_device_linux.cpp"
    #include "tun_device_linux.h"
    #include "killswitch_linux.cpp"
    #include "killswitch_linux.h"
#else
    #error Unsupported platform
#endif

namespace libxtun
{

    std::unique_ptr<Router> Router::create()
    {
#if defined(__linux__) && !defined(__ANDROID__)
        return std::make_unique<LinuxRouter>();
#elif defined(__APPLE__)
        return std::make_unique<MacosRouter>();
#elif defined(_WIN32)
        return std::make_unique<WindowsRouter>();
#else
        return nullptr;
#endif
    }

    std::unique_ptr<TunDevice> createTunDevice()
    {
#if defined(_WIN32)
        return std::make_unique<WindowsTunDevice>();
#elif defined(__APPLE__)
        return std::make_unique<MacosTunDevice>();
#elif defined(__linux__) || defined(__ANDROID__)
        return std::make_unique<LinuxTunDevice>();
#endif
    }

    std::unique_ptr<Killswitch> Killswitch::create(libxtun_killswitch_mode mode)
    {
#if defined(_WIN32)
        return std::make_unique<WindowsKillswitch>();
#elif defined(__APPLE__)
        return std::make_unique<MacosKillswitch>(mode);
#elif defined(__linux__) && !defined(__ANDROID__)
        return std::make_unique<LinuxKillswitch>(mode);
#else
        (void)mode;
        return nullptr;
#endif
    }

}
