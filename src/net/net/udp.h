#ifndef TINY_NET_UDP_H
#define TINY_NET_UDP_H

#include "sock.h"

#pragma pack(1)
typedef struct udp_header_t
{
    // 源端口号
    uint16_t src_port;
    // 目标端口号
    uint16_t dest_port;
    // 数据包长度
    uint16_t length;
    // 校验和
    uint16_t checksum;
} udp_header_t;

typedef struct udp_pkt_t
{
    udp_header_t header;
    uint8_t data[0];
} udp_pkt_t;

typedef struct udp_from_t
{
    ipaddr_t src_ip;
    uint16_t src_port;
} udp_from_t;
#pragma pack()

typedef struct udp_t
{
    sock_t base;
    sock_wait_t recv_wait;
    nlist_t recv_list;
} udp_t;

net_err_t upd_init();

sock_t* udp_create(int family, int protocol);

net_err_t upd_output(const ipaddr_t* dest_ip, uint16_t dest_port, const ipaddr_t* src_ip, uint16_t src_port,
                     pktbuf_t* buf);

net_err_t udp_input(pktbuf_t* buf, const ipaddr_t* src_ip, const ipaddr_t* dest_ip);

net_err_t udp_sendto(sock_t* sock, const uint8_t* buf, size_t len, int flags,
                     const struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t* sent_size);

net_err_t udp_recvfrom(sock_t* sock, uint8_t* buf, size_t len, int flags,
                       const struct x_sockaddr* src, x_socklen_t* src_len, ssize_t* recv_size);

#endif //TINY_NET_UDP_H
