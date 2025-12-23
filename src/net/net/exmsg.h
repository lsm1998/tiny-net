#ifndef TINY_NET_EXMSG_H
#define TINY_NET_EXMSG_H

#include "net_err.h"

typedef enum exmsg_type_t
{
    NET_EXMSG_TYPE_INVALID = 0,
    NET_EXMSG_TYPE_NETIF_IN,
} exmsg_type_t;

typedef struct exmsg_t
{
    exmsg_type_t type;
    // void* data;
    int id;
    long timestamp;
    long reserved;
} exmsg_t;

net_err_t exmsg_init();

net_err_t exmsg_start();

net_err_t exmsg_netif_in();

#endif //TINY_NET_EXMSG_H
