#ifndef TINY_NET_SOCKET_H
#define TINY_NET_SOCKET_H

#include "ipv4.h"
#include "sock.h"

#undef  INADDR_ANY
#define INADDR_ANY         ((uint32_t)0x00000000)

#undef AF_INET
#define AF_INET            2

#undef SOCK_STREAM
#define SOCK_STREAM        1

#undef SOCK_DGRAM
#define SOCK_DGRAM         2

#undef SOCK_RAW
#define SOCK_RAW           3

#undef IPPROTO_ICMP
#define IPPROTO_ICMP       1

#undef SOL_SOCKET
#define SOL_SOCKET         0

#undef SOL_TCP
#define SOL_TCP            6

#undef SO_RCVTIMEO
#define SO_RCVTIMEO        1

#undef SO_SNDTIMEO
#define SO_SNDTIMEO        2

#undef SO_SNDBUF
#define SO_SNDBUF          3

#undef SO_RCVBUF
#define SO_RCVBUF          4

#undef SO_KEEPALIVE
#define SO_KEEPALIVE       8

#undef SO_NONBLOCK
#define SO_NONBLOCK        9

#undef IPPROTO_UDP
#define IPPROTO_UDP        17

#undef IPPROTO_TCP
#define IPPROTO_TCP        6

#undef TCP_KEEPIDLE
#define TCP_KEEPIDLE       4

#undef TCP_KEEPINTVL
#define TCP_KEEPINTVL      5

#undef TCP_KEEPCNT
#define TCP_KEEPCNT        6

typedef struct x_timeval
{
    int tv_sec;
    int tv_usec;
} x_timeval;

#pragma pack(1)
struct x_in_addr
{
    union
    {
        struct
        {
            uint8_t addr0;
            uint8_t addr1;
            uint8_t addr2;
            uint8_t addr3;
        };

        uint32_t s_addr;
        uint8_t addr_array[4];
    };
};

struct x_sockaddr
{
    uint8_t sa_len; // 整个结构的长度，值固定为16
    uint8_t sa_family; // 地址簇：NET_AF_INET
    uint8_t sa_data[14]; // 数据空间
};

struct x_sockaddr_in
{
    uint8_t sin_len; // 整个结构的长度，值固定为16
    uint8_t sin_family; // 地址簇：AF_INET
    uint16_t sin_port; // 端口号
    struct x_in_addr sin_addr; // IP地址
    char sin_zero[8]; // 填充字节
};

struct x_addrinfo
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    x_socklen_t ai_addrlen;
    char* ai_canonname;
    struct x_sockaddr* ai_addr;
    struct x_addrinfo* ai_next;
};

// struct x_socketaddr
// {
//     uint8_t sa_len;
//     uint8_t sa_family;
//     char sa_data[14];
// };
#pragma pack()

#define in_addr x_in_addr
#define socketaddr x_socketaddr
#define sockaddr x_sockaddr

int x_socket(int family, int type, int protocol);

ssize_t x_sendto(int fd, const void* buf, size_t len, int flags, struct x_sockaddr* addr, x_socklen_t addrlen);

ssize_t x_recvfrom(int fd, void* buf, size_t len, int flags, struct x_sockaddr* addr, x_socklen_t* addrlen);

int x_bind(int fd, struct x_sockaddr* addr, x_socklen_t addrlen);

int x_listen(int fd, int backlog);

int x_accept(int fd, struct x_sockaddr* addr, x_socklen_t* addrlen);

int x_connect(int fd, struct x_sockaddr* addr, x_socklen_t addrlen);

ssize_t x_send(int fd, const void* buf, size_t len, int flags);

ssize_t x_recv(int fd, void* buf, size_t len, int flags);

ssize_t x_read(int fd, void* buf, size_t len);

ssize_t x_write(int fd, const void* buf, size_t len);

int x_close(int fd);

int x_setsockopt(int fd, int level, int opt_name, const void* opt_val, int opt_len);

int x_getaddrinfo(const char* node, const char* service, const struct x_addrinfo* hints, struct x_addrinfo** res);

void x_freeaddrinfo(struct x_addrinfo* res);

#endif //TINY_NET_SOCKET_H
