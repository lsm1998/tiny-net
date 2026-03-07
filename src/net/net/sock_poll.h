#ifndef TINY_NET_SOCK_POLL_H
#define TINY_NET_SOCK_POLL_H

#include <stdint.h>

// 事件掩码

// 输入事件
#define X_POLLIN   0x0001u

// 输出事件
#define X_POLLOUT  0x0004u

// 错误事件
#define X_POLLERR  0x0008u

// 连接关闭事件
#define X_POLLHUP  0x0010u

#endif //TINY_NET_SOCK_POLL_H
