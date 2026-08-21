#include "router.h"

#if defined(__linux__) && !defined(__ANDROID__)
#include "router_linux.h"
#include "router_linux.cpp"
#elif defined(__APPLE__)
#include "router_macos.h"
#include "router_macos.cpp"
#elif defined(_WIN32)
#include "router_windows.h"
#include "router_windows.cpp"
#endif

namespace libxtun {

std::unique_ptr<Router> Router::create() {
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

}
