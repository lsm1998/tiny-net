#ifndef TINY_NET_EPOLL_H
#define TINY_NET_EPOLL_H

#include "sock.h"

// epoll_ctl 操作类型
#define EPOLL_CTL_ADD  1  // 添加 fd 到 epoll
#define EPOLL_CTL_MOD  2  // 修改已注册 fd 的事件
#define EPOLL_CTL_DEL  3  // 从 epoll 中删除 fd

// epoll 事件标志（与 poll 兼容）
#define EPOLLIN    0x0001  // 可读
#define EPOLLOUT   0x0004  // 可写
#define EPOLLERR   0x0008  // 错误（始终监听，无需设置）
#define EPOLLHUP   0x0010  // 挂断（始终监听，无需设置）
#define EPOLLET    (1 << 31)  // 边沿触发模式

// epoll 实例最大监听 fd 数量
#define EPOLL_MAX_FDS  64

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

// epoll 注册项
typedef struct x_epoll_entry
{
    int fd;
    uint32_t events; // 监听的事件
    x_epoll_data_t data; // 用户关联数据
    int in_use; // 是否使用中
} x_epoll_entry_t;

// epoll 实例
typedef struct x_epoll
{
    x_epoll_entry_t entries[EPOLL_MAX_FDS]; // 注册的 fd 列表
    int count; // 已注册 fd 数量
    sock_wait_t wait; // 等待信号量
} x_epoll_t;

int x_epoll_create1(int flags);

int x_epoll_create();

int x_epoll_ctl(int epoll_fd, int op, int fd, x_epoll_event_t* event);

int x_epoll_wait(int epoll_fd, x_epoll_event_t* events, int max_events, int timeout);

#define epoll_event x_epoll_event

#define epoll_create1(flags) x_epoll_create1(flags)

#define epoll_create() x_epoll_create()

#define epoll_ctl(epoll_fd, op, fd, event) x_epoll_ctl(epoll_fd, op, fd, event)

#define epoll_wait(epoll_fd, events, max_events, timeout) x_epoll_wait(epoll_fd, events, max_events, timeout)

#endif //TINY_NET_EPOLL_H
