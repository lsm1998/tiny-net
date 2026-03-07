#ifndef TINY_NET_TCP_H
#define TINY_NET_TCP_H

#include "sock.h"
#include "tcp_buf.h"
#include "timer.h"

typedef enum tcp_option_kind_t
{
    TCP_OPTION_END = 0, // 选项结束
    TCP_OPTION_NOP = 1, // 无操作
    TCP_OPTION_MSS = 2, // 最大报文段长度
    TCP_OPTION_WINDOW_SCALE = 3, // 窗口扩大因子
    TCP_OPTION_SACK_PERMITTED = 4, // SACK允许
    TCP_OPTION_SACK = 5, // SACK
    TCP_OPTION_TIMESTAMP = 8, // 时间戳
} tcp_option_kind_t;

typedef struct tcp_option_mss_t
{
    uint8_t kind; // 选项类型
    uint8_t length; // 选项长度
    uint16_t mss; // 最大报文段长度
} tcp_option_mss_t;

#pragma pack(1)
typedef struct tcp_header_t
{
    // 源端口号
    uint16_t src_port;
    // 目标端口号
    uint16_t dest_port;
    // 序列号
    uint32_t seq_num;
    // 确认号
    uint32_t ack_num;

    union
    {
        uint16_t flags;

        struct
        {
#ifdef NET_ENDIAN_LITTLE
            uint16_t f_reserved : 4; // 保留位
            uint16_t f_data_offset : 4; // 数据偏移
            uint16_t f_fin : 1; // 结束标志
            uint16_t f_syn : 1; // 同步标志
            uint16_t f_rst : 1; // 重置标志
            uint16_t f_psh : 1; // 推送标志
            uint16_t f_ack : 1; // 确认标志
            uint16_t f_urg : 1; // 紧急标志
#else
            uint16_t f_data_offset : 4; // 数据偏移
            uint16_t f_reserved : 4; // 保留位
            uint16_t f_urg : 1; // 紧急标志
            uint16_t f_ack : 1; // 确认标志
            uint16_t f_psh : 1; // 推送标志
            uint16_t f_rst : 1; // 重置标志
            uint16_t f_syn : 1; // 同步标志
            uint16_t f_fin : 1; // 结束标志
#endif
        };
    };

    // 窗口大小
    uint16_t window_size;
    // 校验和
    uint16_t checksum;
    // 紧急指针
    uint16_t urgent_ptr;
} tcp_header_t;

typedef struct tcp_pkt_t
{
    tcp_header_t header;
    uint8_t data[0];
} tcp_pkt_t;
#pragma pack()

typedef struct tcp_seg_t
{
    ipaddr_t local_ip;
    ipaddr_t remote_ip;
    tcp_header_t* header;
    pktbuf_t* buf;
    uint32_t data_len;
    uint32_t seq;
    uint32_t seq_len;
} tcp_seg_t;

typedef enum tcp_state_t
{
    TCP_STATE_FREE = 0,
    TCP_STATE_CLOSE,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_MAX,
} tcp_state_t;

typedef enum tcp_ostate_t
{
    TCP_OSTATE_IDLE = 0, // 空闲状态
    TCP_OSTATE_SENDING, // 正在发送数据
    TCP_OSTATE_RETRANS, // 正在重传数据
    TCP_OSTATE_MAX,
} tcp_ostate_t;

typedef struct tcp_t
{
    sock_t base;

    struct tcp_t* parent; // 父连接，监听套接字的tcp_t指针

    tcp_state_t state; // TCP连接状态

    int mss; // 最大报文段长度

    struct
    {
        uint32_t syn_out : 1; // 是否发送过SYN报文
        uint32_t fin_out : 1; // 是否发送过FIN报文
        uint32_t irs_valid : 1; // 是否收到过SYN回复报文
        uint32_t fin_in : 1; // 是否收到过FIN报文
        uint32_t keep_alive : 1; // 是否启用keep-alive
        uint32_t inactive : 1; // 是否处于非活动状态
    } flags;

    struct
    {
        sock_wait_t wait;
        int keep_idle; // keep-alive空闲时间，单位秒
        int keep_interval; // keep-alive探测间隔，单位秒
        int keep_count; // keep-alive探测次数
        int keep_retry; // keep-alive重试次数
        net_timer_t keep_timer; // keep-alive计时器
        int backlog; // 监听套接字的连接请求队列长度
    } conn;

    struct
    {
        tcp_buf_t buf; // 发送缓冲区
        uint8_t* data; // 发送数据缓冲区
        uint32_t next_seq; // 下一个要发送的序列号
        uint32_t un_ack_seq; // 最后一个未确认的序列号
        uint32_t isn; // 初始序列号
        sock_wait_t wait;
        net_timer_t retrans_timer; // 重传计时器
        int retrans_max; // 最大重传次数
        int retrans_count; // 当前重传次数
        int rto; // 重传超时时间，单位毫秒
        tcp_ostate_t ostate; // 发送状态
    } send;

    struct
    {
        tcp_buf_t buf; // 接收缓冲区
        uint8_t* data; // 接收数据缓冲区
        uint32_t next_seq; // 下一个要接收的序列号
        uint32_t isn; // 初始序列号
        sock_wait_t wait;
    } recv;
} tcp_t;

net_err_t tcp_init(void);

void tcp_free(tcp_t* tcp);

tcp_t* tcp_find(const ipaddr_t* local_ip, uint16_t local_port, const ipaddr_t* remote_ip, uint16_t remote_port);

sock_t* tcp_create(int family, int protocol);

size_t tcp_header_size(const tcp_header_t* header);

void tcp_set_header_size(tcp_header_t* header, size_t size);

net_err_t tcp_abort(tcp_t* tcp, net_err_t err);

void tcp_read_options(tcp_t* tcp, tcp_header_t* header);

int tcp_recv_window_size(const tcp_t* tcp);

void tcp_keep_alive_start(tcp_t* tcp, bool enable);

void tcp_keep_alive_reset(tcp_t* tcp);

void tcp_kill_all_timer(const tcp_t* tcp);

bool tcp_backlog_full(const tcp_t* tcp);

tcp_t* tcp_create_child(tcp_t* parent, const tcp_seg_t* seg);

bool tcp_has_pending_conn(const tcp_t* tcp);

#define TCP_SEQ_LE(a, b)        ((int32_t)(a) - (int32_t)(b) <= 0)
#define TCP_SEQ_LT(a, b)        ((int32_t)(a) - (int32_t)(b) < 0)

#endif //TINY_NET_TCP_H
