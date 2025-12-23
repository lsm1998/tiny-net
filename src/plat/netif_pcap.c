#include "netif_pcap.h"
#include "sys_plat.h"
#include "exmsg.h"

void recv_thread(void* arg)
{
    plat_printf("pcap recv_thread started\n");
    while (1)
    {
        sys_sleep(500);
        exmsg_netif_in();
    }
}

void send_thread(void* arg)
{
    plat_printf("pcap send_thread started\n");
    while (1)
    {
        sys_sleep(100);
    }
}

net_err_t netif_pcap_open(void)
{
    const sys_thread_t recv_th = sys_thread_create(recv_thread, NULL);
    if (recv_th == SYS_THREAD_INVALID)
    {
        return NET_ERR_SYS;
    }
    const sys_thread_t send_th = sys_thread_create(send_thread, NULL);
    if (send_th == SYS_THREAD_INVALID)
    {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}
