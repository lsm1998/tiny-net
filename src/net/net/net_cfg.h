#ifndef TINY_NET_NET_CFG_H
#define TINY_NET_NET_CFG_H

// 大小端模式
// 如果是大端模式，定义为0
// 如果是小端模式，定义为1
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NET_ENDIAN_LITTLE 1
#elif __BYTE_ORDER__== __ORDER_BIG_ENDIAN__
#define NET_ENDIAN_LITTLE 0
#else
// 默认小端模式
#define NET_ENDIAN_LITTLE 1
#endif


// 消息队列大小
#define EXMSG_QUEUE_SIZE 10

// 数据包缓冲区有效负载大小
#define PKTBUF_PAYLOAD_SIZE 128

// 数据包缓冲区块数量
#define PKTBUF_BLK_COUNT 100

// 数据包缓冲区数量
#define PKTBUF_BUF_COUNT 100

// 网络接口硬件地址长度
#define NETIF_HWADDR_LEN 10

// 网络接口名称最大长度
#define NETIF_NAME_LEN 10

// 网络接口输入队列大小
#define NETIF_IN_QUEUE_SIZE 128

// 网络接口输出队列大小
#define NETIF_OUT_QUEUE_SIZE 128

// 网络接口设备数量
#define NETIF_DEV_CNT 10

// 定时器名称最大长度
#define TIMER_NAME_LEN 16

// ARP 缓存大小
#define ARP_CACHE_SIZE 50

// ARP 最大等待发送的数据包数量
#define ARP_MAX_PKT_WAITING 5

// ARP 定时器超时时间，单位：秒
#define ARP_TIMER_TMO 1

// ARP 缓存项稳定状态超时时间，单位：秒
#define ARP_ENTRY_STABLE_TMO 120

// ARP 缓存项等待解析超时时间，单位：秒
#define ARP_ENTRY_PENDING_TMO 5

// ARP 最大重试次数
#define ARP_MAX_RETRY_COUNT 5

// IP协议版本
#define NET_VERSION_IPV4 4

// 分片最大数量
#define IPV4_FRAGS_MAX_NR 5

// 分片缓冲区最大数量
#define IPV4_FRAGS_BUFFER_MAX_NR 20

// 原始套接字最大数量
#define RAW_MAX_NR 64

// UDP套接字最大数量
#define UDP_MAX_NR 64

// TCP套接字最大数量
#define TCP_MAX_NR 64

// 套接字最大文件描述符数量
#define SOCKET_MAX_FD (RAW_MAX_NR + UDP_MAX_NR + TCP_MAX_NR)

// 原始套接字接收队列长度
#define RAW_RECV_QUEUE_LEN 128

// UDP套接字接收队列长度
#define UDP_RECV_QUEUE_LEN 128

// 路由表最大条目数量
#define IPV4_ROUTE_TABLE_MAX_NR 32

// 空端口号
#define NET_PORT_EMPTY 0

// 动态端口范围开始
#define NET_PORT_DYN_START 49152

// 动态端口范围结束
#define NET_PORT_DYN_END 65535

// TCP发送缓冲区大小
#define TCP_SEND_BUF_SIZE 4096

// TCP接收缓冲区大小
#define TCP_RECV_BUF_SIZE 4096

// TCP默认最大报文段长度
#define TCP_DEFAULT_MSS 536

// keep-alive空闲时间，单位秒
#define TCP_KEEP_IDLE 7200

// keep-alive探测间隔，单位秒
#define TCP_KEEP_INTERVAL 75

// keep-alive探测次数
#define TCP_KEEP_COUNT 9

// TCP监听套接字的最大等待连接数量
#define TCP_BACKLOG_MAX 128

// 关闭等待状态超时时间，单位秒
#define NET_CLOSE_WAIT_TIMEOUT 10

// TCP TIME-WAIT状态持续时间，单位秒（2MSL）
#define TCP_TIMEOUT_MSL 30

// IP地址字符串长度
#define INET_ADDRSTRLEN 16

#endif //TINY_NET_NET_CFG_H
