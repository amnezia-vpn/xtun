#ifndef NET_SYS_H
#define NET_SYS_H

#if defined(_WIN32)
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <poll.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#endif // NET_SYS_H
