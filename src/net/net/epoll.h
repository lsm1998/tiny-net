#ifndef TINY_NET_EPOLL_H
#define TINY_NET_EPOLL_H

#include "sock.h"
#include "rb_tree.h"

// epoll_ctl 操作类型
#undef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD  1  // 添加 fd 到 epoll

#undef EPOLL_CTL_MOD
#define EPOLL_CTL_MOD  2  // 修改已注册 fd 的事件

#undef EPOLL_CTL_DEL
#define EPOLL_CTL_DEL  3  // 从 epoll 中删除 fd

// epoll 事件标志
#undef EPOLLIN
#define EPOLLIN    0x0001  // 可读

#undef EPOLLOUT
#define EPOLLOUT   0x0004  // 可写

#undef EPOLLERR
#define EPOLLERR   0x0008  // 错误

#undef EPOLLHUP
#define EPOLLHUP   0x0010  // 挂断

#undef EPOLLET
#define EPOLLET    (1 << 31)  // 边沿触发模式

// epoll 实例最大监听 fd 数量
#define EPOLL_MAX_FDS  64

typedef struct x_epoll x_epoll_t;

typedef union x_epoll_data
{
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} x_epoll_data_t;

typedef struct x_epoll_event
{
    uint32_t events; // epoll 事件掩码
    x_epoll_data_t data; // 用户数据
} x_epoll_event_t;


typedef struct x_epoll_item
{
    int in_use;
    int fd;
    uint32_t events;
    uint32_t last_ready;
    uint32_t ready_events;
    int queued;
    int on_sock_list;
    x_epoll_data_t data;
    sock_t* sock;
    struct x_epoll* epoll;
    rb_node_t rb_node;
    nlist_node_t ready_node;
    nlist_node_t sock_node;
} x_epoll_item_t;

struct x_epoll
{
    int fd;
    int in_use;
    int closed;
    int waiters;
    int count;
    rb_tree_t interest_tree;
    nlist_t ready_list;
    x_epoll_item_t items[EPOLL_MAX_FDS];
    sys_sem_t wait_sem;
    sys_mutex_t locker;
};

int x_epoll_create1(int flags);

int x_epoll_create();

int x_epoll_ctl(int epoll_fd, int op, int fd, const x_epoll_event_t* event);

int x_epoll_wait(int epoll_fd, x_epoll_event_t* events, int max_events, int timeout);

int x_epoll_close(int epoll_fd);

uint32_t x_epoll_poll_events(int fd);

void x_epoll_sock_wakeup(const struct sock_t* sock);

void x_epoll_sock_close(const struct sock_t* sock, int fd);

void x_epoll_fd_recheck(int fd);

#define epoll_event x_epoll_event

#define epoll_create1(flags) x_epoll_create1(flags)

#define epoll_create() x_epoll_create()

#define epoll_ctl(epoll_fd, op, fd, event) x_epoll_ctl(epoll_fd, op, fd, event)

#define epoll_wait(epoll_fd, events, max_events, timeout) x_epoll_wait(epoll_fd, events, max_events, timeout)

#endif //TINY_NET_EPOLL_H
