#include "arp.h"
#include "ether.h"
#include "protocol.h"
#include "dbug.h"
#include "netif.h"
#include "tool.h"
#include "ipv4.h"

#if DBG_DISPLAY_ENABLE(DBG_MOD_ETHER)
static void display_ether_frame(const char* title, const ether_frame_t* frame, const uint32_t frame_len)
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_ETHER)) return;

    uint16_t protocol = x_ntohs(frame->header.protocol);
    plat_printf("%s: 包大小=%u\n", title, frame_len);
    plat_printf("  目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n",
                frame->header.dest_mac[0], frame->header.dest_mac[1],
                frame->header.dest_mac[2], frame->header.dest_mac[3],
                frame->header.dest_mac[4], frame->header.dest_mac[5]);
    plat_printf("  源MAC地址:  %02X:%02X:%02X:%02X:%02X:%02X\n",
                frame->header.src_mac[0], frame->header.src_mac[1],
                frame->header.src_mac[2], frame->header.src_mac[3],
                frame->header.src_mac[4], frame->header.src_mac[5]);
    plat_printf("  协议类型: 0x%04X\n", protocol);
    switch (protocol)
    {
    case PROTOCOL_TYPE_ARP:
        plat_printf("    协议: ARP\n");
        break;
    case PROTOCOL_TYPE_IPv4:
        plat_printf("    协议: IPv4\n");
        break;
    default:
        plat_printf("    协议: 未知\n");
        break;
    }
}
#endif

static net_err_t frame_is_valid(const ether_frame_t* frame, const uint32_t frame_len)
{
    if (frame_len < sizeof(ether_header_t) || frame_len > sizeof(ether_frame_t))
    {
        return NET_ERR_FRAME;
    }
    return NET_ERR_OK;
}

// 打开函数指针
static net_err_t ether_open(netif_t* netif)
{
    return arp_make_gratuitous_request(netif);
}

// 关闭函数指针
static void ether_close(netif_t* netif)
{
    arp_clear(netif);
}

// 输入函数指针
static net_err_t ether_input(netif_t* netif, pktbuf_t* buf)
{
    dbug_info(DBG_MOD_ETHER, "ether_input: received pktbuf=%p, len=%d", buf, buf->total_size);

    // 设置包的连续性
    net_err_t err = pktbuf_set_cont(buf, sizeof(ether_header_t));
    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_ETHER, "ether_input: pktbuf_set_cont failed, err=%d", err);
        return err;
    }

    ether_frame_t* frame = (ether_frame_t*)pktbuf_data(buf);

    err = frame_is_valid(frame, buf->total_size);
    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_ETHER, "ether_input: invalid ether frame, err=%d", err);
        return err;
    }

    uint16_t protocol = x_ntohs(frame->header.protocol);
    switch (protocol)
    {
    case PROTOCOL_TYPE_ARP:
        dbug_info(DBG_MOD_ETHER, "收到ARP数据包");
        // 移除以太网头
        if ((err = pktbuf_remove_header(buf, sizeof(ether_header_t))) != NET_ERR_OK)
        {
            dbug_warn(DBG_MOD_ETHER, "ether_input: pktbuf_remove_header failed, err=%d", err);
            return err;
        }
        return arp_in(netif, buf);
    case PROTOCOL_TYPE_IPv4:
        dbug_info(DBG_MOD_ETHER, "收到IPv4数据包");
        arp_update_from_ip_buf(netif, buf);

        // 移除以太网头
        if ((err = pktbuf_remove_header(buf, sizeof(ether_header_t))) != NET_ERR_OK)
        {
            dbug_warn(DBG_MOD_ETHER, "ether_input: pktbuf_remove_header failed, err=%d", err);
            return err;
        }
        return ipv4_input(netif, buf);
    default:
        dbug_warn(DBG_MOD_ETHER, "不支持的协议 protocol 0x%04X", protocol);
        break;
    }

    pktbuf_free(buf);
    return NET_ERR_OK;
}

// 输出函数指针
static net_err_t ether_output(netif_t* netif, ipaddr_t* ipaddr, pktbuf_t* buf)
{
    const uint8_t* hwaddr = arp_find(netif, ipaddr);
    if (hwaddr != NULL)
    {
        // 已缓存，直接发送
        return ether_raw_out(netif, PROTOCOL_TYPE_IPv4, hwaddr, buf);
    }

    // 通过ARP解析MAC地址并发送
    return arp_resolve(netif, ipaddr, buf);
}

net_err_t ether_init()
{
    static const link_layer_t ether_link_layer = {
        .type = NETIF_TYPE_ETHERNET,
        .open = ether_open,
        .close = ether_close,
        .input = ether_input,
        .output = ether_output,
    };

    if (DBG_DISPLAY_CHECK(DBG_MOD_ETHER))
    {
        plat_printf("ether_header_t sizeof=%lu \n", sizeof(ether_header_t));
        plat_printf("ether_frame_t sizeof=%lu \n", sizeof(ether_frame_t));
    }

    return netif_register_link_layer(&ether_link_layer);
}

const uint8_t* ether_broadcast_addr()
{
    static const uint8_t broadcast_addr[ETHER_HWADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return broadcast_addr;
}

net_err_t ether_raw_out(netif_t* netif, const uint16_t protocol, const uint8_t* dest_mac, pktbuf_t* buf)
{
    net_err_t err = NET_ERR_OK;
    int size = pktbuf_total(buf);
    if (size < ETHER_PAYLOAD_MIN_LEN)
    {
        // 填充到最小长度
        if ((err = pktbuf_resize(buf, ETHER_PAYLOAD_MIN_LEN)) != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_ETHER, "ether_raw_out: pktbuf_resize failed, err=%d", err);
            return err;
        }
        pktbuf_reset_access(buf);
        if ((err = pktbuf_seek(buf, size)) != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_ETHER, "ether_raw_out: pktbuf_seek failed, err=%d", err);
            return err;
        }
        if ((err = pktbuf_fill(buf, 0, ETHER_PAYLOAD_MIN_LEN - size)) != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_ETHER, "ether_raw_out: pktbuf_fill failed, err=%d", err);
            return err;
        }
    }

    // 添加以太网头
    if ((err = pktbuf_add_header(buf, sizeof(ether_header_t), true)) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ETHER, "ether_raw_out: pktbuf_add_header failed, err=%d", err);
        return err;
    }

    ether_frame_t* frame = (ether_frame_t*)pktbuf_data(buf);
    plat_memcpy(frame->header.dest_mac, dest_mac, ETHER_HWADDR_LEN);
    plat_memcpy(frame->header.src_mac, netif->hwaddr.addr, ETHER_HWADDR_LEN);
    frame->header.protocol = x_htons(protocol);

    display_ether_frame("发送以太网数据包", frame, pktbuf_total(buf));

    // 如果发送给自己的MAC地址，则不需要通过网卡发送，直接放入接收队列
    if (plat_memcmp(netif->hwaddr.addr, dest_mac, ETHER_HWADDR_LEN) == 0)
    {
        return netif_put_in(netif, buf, -1);
    }

    // 将数据包放入网卡的发送队列
    if ((err = netif_put_out(netif, buf, -1)) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ETHER, "ether_raw_out: netif_put_out failed, err=%d", err);
        return err;
    }

    return netif->opts->linkoutput(netif);
}
