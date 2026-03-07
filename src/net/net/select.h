#ifndef TINY_NET_SELECT_SERVE_H
#define TINY_NET_SELECT_SERVE_H

#include "socket.h"

// 计算fd_set中每个uint32_t可以存储多少个文件描述符的位
#define X_NFDBITS ((int)(sizeof(uint32_t) * 8))

// 计算fd_set中需要多少个uint32_t来存储NET_FD_MAX个文件描述符
#define X_FDSET_WORDS ((NET_FD_MAX + X_NFDBITS - 1) / X_NFDBITS)

typedef struct x_fd_set
{
    uint32_t bits[X_FDSET_WORDS];
} x_fd_set;

// 设置set中所有位为0
static inline void x_fd_zero_bits(x_fd_set* set)
{
    if (set == NULL)
    {
        return;
    }

    for (int i = 0; i < X_FDSET_WORDS; ++i)
    {
        set->bits[i] = 0;
    }
}

// 设置set中fd对应的位为1
static inline void x_fd_set_bits(const int fd, x_fd_set* set)
{
    if (set == NULL || fd < 0 || fd >= NET_FD_MAX)
    {
        return;
    }

    set->bits[fd / X_NFDBITS] |= (uint32_t)1u << (fd % X_NFDBITS);
}

// 设置set中fd对应的位为0
static inline void x_fd_clr_bits(const int fd, x_fd_set* set)
{
    if (set == NULL || fd < 0 || fd >= NET_FD_MAX)
    {
        return;
    }

    set->bits[fd / X_NFDBITS] &= ~((uint32_t)1u << (fd % X_NFDBITS));
}

// 判断set中fd对应的位是否为1
static inline int x_fd_isset_bits(const int fd, const x_fd_set* set)
{
    if (set == NULL || fd < 0 || fd >= NET_FD_MAX)
    {
        return 0;
    }

    return (set->bits[fd / X_NFDBITS] & 1u << (fd % X_NFDBITS)) != 0;
}

net_err_t x_select_init(void);

void x_select_wakeup(void);

int x_select(int n_fds, x_fd_set* read_fds, x_fd_set* write_fds, x_fd_set* except_fds, const x_timeval* timeout);

#endif //TINY_NET_SELECT_SERVE_H
