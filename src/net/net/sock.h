#ifndef TINY_NET_SOCK_H
#define TINY_NET_SOCK_H

#include "exmsg.h"
#include "net_err.h"
#include "sock_poll.h"

typedef int x_socklen_t;

struct sock_t;

struct x_sockaddr;

struct sock_req_t;

struct x_epoll;

#define SOCK_WAIT_READ (1<<0)
#define SOCK_WAIT_WRITE (1<<1)
#define SOCK_WAIT_CONN (1<<2)
#define SOCK_WAIT_ALL (SOCK_WAIT_READ | SOCK_WAIT_WRITE | SOCK_WAIT_CONN)

typedef struct sock_wait_t
{
    sys_sem_t sem;
    net_err_t err;
    int waiting;
} sock_wait_t;

net_err_t sock_wait_init(sock_wait_t* wait);

void sock_wait_destroy(sock_wait_t* wait);

void sock_wait_add(sock_wait_t* wait, int timeout, struct sock_req_t* req);

net_err_t sock_wait_enter(const sock_wait_t* wait, int timeout);

void sock_wait_leave(sock_wait_t* wait, net_err_t err);

void sock_wakeup(const struct sock_t* sock, int type, net_err_t err);

typedef struct sock_ops_t
{
    net_err_t (*close)(struct sock_t* sock);
    net_err_t (*setsockopt)(struct sock_t* sock, int level, int opt_name, const void* opt_val, int opt_len);
    net_err_t (*sendto)(struct sock_t* sock, const uint8_t* buf, size_t len, int flags,
                        const struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t* sent_size);
    net_err_t (*recvfrom)(struct sock_t* sock, uint8_t* buf, size_t len, int flags,
                          const struct x_sockaddr* src, x_socklen_t* src_len, ssize_t* recv_size);
    net_err_t (*setopt)(struct sock_t* sock, int level, int opt_name, const void* opt_val, int opt_len);
    net_err_t (*connect)(struct sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen);
    net_err_t (*send)(struct sock_t* sock, const uint8_t* buf, size_t len, int flags, ssize_t* sent_size);
    net_err_t (*recv)(struct sock_t* sock, uint8_t* buf, size_t len, int flags, ssize_t* recv_size);
    net_err_t (*bind)(struct sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen);
    void (*destroy)(struct sock_t* sock);
    net_err_t (*listen)(struct sock_t* sock, int backlog);
    net_err_t (*accept)(struct sock_t* sock, struct x_sockaddr* addr, x_socklen_t* addrlen, struct sock_t** new_sock);
    uint32_t (*poll)(struct sock_t* sock);
} sock_ops_t;

typedef struct sock_t
{
    uint16_t local_port;
    uint16_t remote_port;
    ipaddr_t local_ip;
    ipaddr_t remote_ip;
    const sock_ops_t* ops;
    int family;
    int protocol;
    net_err_t err;
    int recv_timeout;
    int send_timeout;
    int send_buf_size;
    int recv_buf_size;
    int nonblock; // 非阻塞模式

    sock_wait_t* recv_wait;
    sock_wait_t* send_wait;
    sock_wait_t* conn_wait;
    nlist_t epoll_list;
    nlist_node_t node;
} sock_t;

typedef enum x_fd_type_t
{
    X_FD_TYPE_NONE = 0,
    X_FD_TYPE_SOCKET,
    X_FD_TYPE_EPOLL,
} x_fd_type_t;

typedef struct x_socket_t
{
    x_fd_type_t type; // 资源类型：socket或epoll
    union
    {
        sock_t* sock;
        struct x_epoll* epoll;
        void* ptr;
    };
} x_socket_t;

typedef struct sock_create_t
{
    int family;
    int type;
    int protocol;
} sock_create_t;

typedef struct sock_data_t
{
    uint8_t* buf;
    size_t len;
    int flags;
    struct x_sockaddr* addr;
    x_socklen_t* addrlen;
    ssize_t transferred_len;
} sock_data_t;

typedef struct sock_opt_t
{
    int level;
    int opt_name;
    const void* opt_val;
    int opt_len;
} sock_opt_t;

typedef struct sock_conn_t
{
    struct x_sockaddr* addr;
    x_socklen_t addrlen;
} sock_conn_t;

typedef struct sock_bind_t
{
    struct x_sockaddr* addr;
    x_socklen_t addrlen;
} sock_bind_t;

typedef struct sock_listen_t
{
    int backlog;
} sock_listen_t;

typedef struct sock_accept_t
{
    struct x_sockaddr* addr;
    x_socklen_t* addrlen;
    int client_fd;
} sock_accept_t;

typedef struct sock_req_t
{
    int fd;
    sock_wait_t* wait;
    int wait_timeout;

    union
    {
        sock_create_t create;
        sock_data_t data;
        sock_opt_t opt;
        sock_conn_t conn;
        sock_bind_t bind;
        sock_listen_t listen;
        sock_accept_t accept;
    };
} sock_req_t;

net_err_t socket_init(void);

net_err_t socket_create_req_in(const func_msg_t* msg);

net_err_t socket_sendto_req_in(const func_msg_t* msg);

net_err_t socket_recvfrom_req_in(const func_msg_t* msg);

net_err_t socket_setsockopt_req_in(const func_msg_t* msg);

net_err_t socket_close_req_in(const func_msg_t* msg);

net_err_t socket_connect_req_in(const func_msg_t* msg);

net_err_t socket_bind_req_in(const func_msg_t* msg);

net_err_t socket_send_req_in(const func_msg_t* msg);

net_err_t socket_recv_req_in(const func_msg_t* msg);

net_err_t socket_listen_req_in(const func_msg_t* msg);

net_err_t socket_accept_req_in(const func_msg_t* msg);

net_err_t socket_destroy_req_in(const func_msg_t* msg);

net_err_t sock_init(sock_t* sock, int family, int protocol, const sock_ops_t* ops);

net_err_t sock_setopt(sock_t* sock, int level, int opt_name, const void* opt_val, int opt_len);

net_err_t sock_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen);

net_err_t sock_send(sock_t* sock, const uint8_t* buf, size_t len, int flags, ssize_t* sent_size);

net_err_t sock_recv(sock_t* sock, uint8_t* buf, size_t len, int flags, ssize_t* recv_size);

net_err_t sock_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen);

void sock_free(const sock_t* sock);

x_fd_type_t sock_fd_type(int fd);

int sock_fd_alloc_socket(sock_t* sock);

int sock_fd_alloc_epoll(struct x_epoll* epoll);

sock_t* sock_fd_get_socket(int fd);

struct x_epoll* sock_fd_get_epoll(int fd);

void sock_fd_release(int fd);

int sock_fd_poll_events(int fd, uint32_t* events);

#endif //TINY_NET_SOCK_H
