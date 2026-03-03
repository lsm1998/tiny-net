#ifndef TINY_NET_PING_H
#define TINY_NET_PING_H

#include <stdint.h>
#include "icmp_v4.h"
#include "ipv4.h"

#define PING_BUFFER_SIZE 4096

typedef struct echo_request_t
{
    // icmp头部
    icmp_v4_header_t icmp_header;
    // 数据
    char data[PING_BUFFER_SIZE];
} echo_request_t;

typedef struct echo_reply_t
{
    // ip头部
    ipv4_header_t ip_header;
    // icmp头部
    icmp_v4_header_t icmp_header;
    // 数据
    char data[PING_BUFFER_SIZE];
} echo_reply_t;

typedef struct ping_t
{
    // 请求报文
    echo_request_t request;
    // 应答报文
    echo_reply_t reply;
} ping_t;

// 发送ping请求
void ping_run(ping_t* ping, const char* dest, int count, int size, int interval,int timeout);

#endif //TINY_NET_PING_H
