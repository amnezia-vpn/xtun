#include "router.h"

#if defined(__linux__)
#include "router_linux.h"
#elif defined(__APPLE__)
#include "router_macos.h"
#endif

namespace libxtun {

std::unique_ptr<Router> Router::create() {
#if defined(__linux__)
    return std::make_unique<LinuxRouter>();
#elif defined(__APPLE__)
    return std::make_unique<MacosRouter>();
#else
    return nullptr;
#endif
}

}
