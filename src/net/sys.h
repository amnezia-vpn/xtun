#ifndef NET_SYS_H
#define NET_SYS_H

#if defined(_WIN32)
    #include <windows.h>  // IWYU pragma: export
    #include <winsock2.h> // IWYU pragma: export
    #include <ws2tcpip.h> // IWYU pragma: export
#else
    #include <arpa/inet.h>  // IWYU pragma: export
    #include <netinet/in.h> // IWYU pragma: export
    #include <poll.h>       // IWYU pragma: export
    #include <sys/socket.h> // IWYU pragma: export
    #include <unistd.h>     // IWYU pragma: export
#endif

#endif // NET_SYS_H
