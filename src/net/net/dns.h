#ifndef TINY_NET_DNS_H
#define TINY_NET_DNS_H

#include "ipaddr.h"
#include "net_err.h"
#include "net_cfg.h"
#include "exmsg.h"
#include "udp.h"

#define DNS_QUERY_CLASS_INET            1     // 查询类：1 - 表示互联网类
#define DNS_QUERY_TYPE_A                1       // IPv4地址纪录

typedef struct dns_req_t
{
    char domain[DNS_DOMAIN_MAX_LEN]; // 查询的域名
    net_err_t err; // 查询结果
    int query_id; // 查询发包使用的id
    ipaddr_t ipaddr; // 查询到的IP地址
    sys_sem_t wait_sem; // 同步查询结果的信号量
    uint8_t retry_timeout; // 重试查询的秒数
    uint8_t retry_cnt; // 重试查询的次数
    nlist_node_t node; // 查询链接结点
} dns_req_t;

#pragma pack(1)
typedef struct dns_header_t
{
    uint16_t id; // 事务ID
    union
    {
        uint16_t all;

#if NET_ENDIAN_LITTLE
        struct
        {
            uint16_t rcode : 4; // 响应码
            uint16_t cd : 1; // 禁用安全检查（1）
            uint16_t ad : 1; // 信息已授权（1）
            uint16_t z : 1; // 保底为0
            uint16_t ra : 1; // 服务器是否支持递归查询(1)
            uint16_t rd : 1; // 告诉服务器执行递归查询(1)，0 容许迭代查询
            uint16_t tc : 1; // 可截断(1)，即UDP长超512字节时，可只返回512字节
            uint16_t aa : 1; // 授权回答
            uint16_t opcode : 4; // 操作码(缺省为0)
            uint16_t qr : 1;
        };
#else
        struct
        {
            uint16_t qr : 1;
            uint16_t opcode : 4; // 操作码(缺省为0)
            uint16_t aa : 1; // 授权回答
            uint16_t tc : 1; // 可截断(1)，即UDP长超512字节时，可只返回512字节
            uint16_t rd : 1; // 告诉服务器执行递归查询(1)，0 容许迭代查询
            uint16_t ra : 1; // 服务器是否支持递归查询(1)
            uint16_t z : 1; // 保底为0
            uint16_t ad : 1; // 信息已授权（1）
            uint16_t cd : 1; // 禁用安全检查（1）
            uint16_t rcode : 5; // 响应码
        };
#endif
    } flags;

    uint16_t qdcount; // 查询数/区域数
    uint16_t ancount; // 回答/先决条件数
    uint16_t nscount; // 授权纪录数/更新数
    uint16_t arcount; // 额外信息数
} dns_header_t;

typedef struct dns_qfield_t
{
    uint16_t type; // 查询类型
    uint16_t class; // 查询类
} dns_qfield_t;
#pragma pack()

typedef struct dns_entry_t
{
    int ttl; // 该表项的生存时间
    ipaddr_t ipaddr; // 对应的IP地址
    char domain_name[DNS_DOMAIN_MAX_LEN]; //  域名最大长度
} dns_entry_t;

void dns_init();

void dns_in();

dns_req_t* dns_alloc_req();

void dns_free_req(dns_req_t* req);

net_err_t dns_query_req_in(const func_msg_t* msg);

bool dns_is_arrival(const udp_t* udp);

#endif //TINY_NET_DNS_H
