#include "common.h"
#include "dbug.h"
#include "exmsg.h"
#include "netif.h"
#include "timer.h"
#include "loop.h"
#include "arp.h"
#include "ether.h"
#include "ipv4.h"
#include "netif_pcap.h"
#include "sock.h"
#include "raw.h"
#include "sys_plat.h"
#include "udp.h"
#include "tcp.h"
#include "dns.h"

// 动态获取的网络接口信息
static netif_info_t netif_info;
static char local_ip[16];
static char gateway_ip[16];
static char virtual_ip[16];

// 虚拟网卡操作函数
pcap_data_t netdev_0 = {
    .ipaddr = local_ip,
    .hwaddr = (uint8_t[]){0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
};

static net_err_t netdev_init(void)
{
    // 动态获取本机网络接口信息
    if (pcap_get_first_netif(&netif_info) < 0)
    {
        dbug_error(DBG_MOD_COMMON, "netdev_init: failed to get network interface info");
        return NET_ERR_SYS;
    }

    // 复制本地IP和网关
    plat_strcpy(local_ip, netif_info.ip);
    plat_strcpy(gateway_ip, netif_info.gateway);

    // 生成虚拟IP地址
    unsigned int a, b, c, d;
    if (sscanf(netif_info.ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4)
    {
        // 将最后一个字节设为95或96
        unsigned int virtual_d = (d == 95) ? 96 : 95;
        sprintf(virtual_ip, "%u.%u.%u.%u", a, b, c, virtual_d);
    }
    else
    {
        dbug_error(DBG_MOD_COMMON, "netdev_init: invalid IP address format");
        return NET_ERR_SYS;
    }

    dbug_info(DBG_MOD_COMMON, "Network configuration:");
    dbug_info(DBG_MOD_COMMON, "  Local IP:   %s", local_ip);
    dbug_info(DBG_MOD_COMMON, "  Gateway:    %s", gateway_ip);
    dbug_info(DBG_MOD_COMMON, "  Virtual IP: %s", virtual_ip);
    dbug_info(DBG_MOD_COMMON, "  Netmask:    %s", netif_info.netmask);

    netif_t* netif = netif_open("vnet0", &netdev_ops, &netdev_0);
    if (!netif)
    {
        dbug_error(DBG_MOD_COMMON, "netdev_init: failed to open network interface");
        return NET_ERR_SYS;
    }

    ipaddr_t ipaddr;
    ipaddr_t netmask;
    ipaddr_t gateway;

    ipaddr4_form_str(&ipaddr, virtual_ip);
    ipaddr4_form_str(&netmask, netif_info.netmask);
    ipaddr4_form_str(&gateway, gateway_ip);

    netif_set_addr(netif, &ipaddr, &netmask, &gateway);

    netif_set_hwaddr(netif, netdev_0.hwaddr, 6);

    netif_set_active(netif);

    netif_set_default(netif);

    return NET_ERR_OK;
}

net_err_t tiny_net_init(void)
{
    // pktbuf初始化
    pktbuf_init();

    // 消息模块初始化
    exmsg_init();

    // 网络接口初始化
    netif_init();

    // 定时器初始化
    net_timer_init();

    // ARP模块初始化
    arp_init();

    // IPv4协议栈初始化
    ipv4_init();

    // 以太网卡初始化
    ether_init();

    // 虚拟网卡初始化
    netdev_init();

    // 工作线程
    exmsg_start();

    // Socket模块初始化
    socket_init();

    // 原始套接字模块初始化
    raw_init();

    // UDP模块初始化
    upd_init();

    // DNS模块初始化
    dns_init();

    // TCP模块初始化
    tcp_init();

    // 回环网卡初始化
    loop_init();

    return NET_ERR_OK;
}
