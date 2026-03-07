#ifndef TINY_NET_TCP_OUT_H
#define TINY_NET_TCP_OUT_H

#include "net_err.h"
#include "tcp.h"

typedef enum tcp_out_event_t
{
    TCP_OUT_EVENT_SEND = 0, // 发送数据
    TCP_OUT_EVENT_TRANSMIT = 1, // 传输数据
    TCP_OUT_EVENT_TIMEOUT = 2, // 超时事件
} tcp_out_event_t;

net_err_t tcp_send_reset(const tcp_seg_t* seg);

net_err_t tcp_send_syn(tcp_t* tcp);

net_err_t tcp_ack_process(tcp_t* tcp, const tcp_seg_t* seg);

net_err_t tcp_send_ack(tcp_t* tcp, tcp_seg_t* seg);

net_err_t tcp_send_fin(tcp_t* tcp);

net_err_t tcp_send_keep_alive(const tcp_t* tcp);

net_err_t tcp_send_reset_with_tcp(const tcp_t* tcp);

net_err_t tcp_transmit(tcp_t* tcp);

int tcp_write_send_buf(tcp_t* tcp, const uint8_t* buf, size_t len);

const char* tcp_ostate_name(tcp_ostate_t ostate);

void tcp_out_event(tcp_t* tcp, tcp_out_event_t event);

#endif //TINY_NET_TCP_OUT_H
