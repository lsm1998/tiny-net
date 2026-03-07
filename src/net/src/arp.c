#include "arp.h"
#include "dbug.h"
#include "ipv4.h"
#include "mblock.h"
#include "tool.h"
#include "protocol.h"
#include "timer.h"

#define to_scan_cnt(tmo_sec) ((tmo_sec) / ARP_TIMER_TMO)

static net_timer_t cache_timer;

static arp_entity_t cache_tbl[ARP_CACHE_SIZE];

static mblock_t cache_block;

static nlist_t cache_list;

// 用于初始化缓存项时的空MAC地址
static const uint8_t empty_hwaddr[ETHER_HWADDR_LEN] = {0};

#if DBG_DISPLAY_ENABLE(DBG_MOD_ARP)
static void display_arp_entity(const arp_entity_t* entity)
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_ARP)) return;

    plat_printf("ARP Entity:\n");
    plat_printf("  IP:");
    dbug_dump_ipaddr((ipaddr_t*)&entity->p_addr);
    plat_printf("  MAC:");
    dbug_dump_hwaddr(entity->hwaddr, ETHER_HWADDR_LEN);
    plat_printf("  Netif:%s ", entity->netif ? entity->netif->name : "NULL");
    plat_printf("  Timeout:%d ms ", entity->timeout);
    plat_printf("  Retry Count:%d ", entity->retry_cnt);
    plat_printf("  State:%s ", entity->state == NET_ARP_RESOLVE ? "stable" : "pending");
    plat_printf("  buf:%d\n", nlist_count(&entity->buf_list));
}

static void display_arp_tbl()
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_ARP)) return;

    plat_printf("ARP table start=======================:\n");
    arp_entity_t* entity = cache_tbl;
    for (int i = 0; i < ARP_CACHE_SIZE; i++, entity++)
    {
        if (entity->state != NET_ARP_RESOLVE)
        {
            continue;
        }
        display_arp_entity(entity);
    }
    plat_printf("ARP table end=======================:\n");
}

static void display_arp_pkt(const arp_pkt_t* pkt)
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_ARP)) return;

    plat_printf("ARP Packet:\n");
    plat_printf("  Hardware Type: %u\n", x_ntohs(pkt->h_type));
    plat_printf("  Protocol Type: 0x%04X\n", x_ntohs(pkt->p_type));
    plat_printf("  Hardware Address Length: %u\n", pkt->hw_len);
    plat_printf("  Protocol Address Length: %u\n", pkt->p_len);
    plat_printf("  Opcode: %u\n", x_ntohs(pkt->opcode));
    plat_printf("  Sender MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                pkt->sender_hwaddr[0], pkt->sender_hwaddr[1], pkt->sender_hwaddr[2],
                pkt->sender_hwaddr[3], pkt->sender_hwaddr[4], pkt->sender_hwaddr[5]);
    plat_printf("  Sender IP Address: %d.%d.%d.%d\n",
                pkt->sender_addr[0], pkt->sender_addr[1],
                pkt->sender_addr[2], pkt->sender_addr[3]);
    plat_printf("  Target MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                pkt->target_hwaddr[0], pkt->target_hwaddr[1], pkt->target_hwaddr[2],
                pkt->target_hwaddr[3], pkt->target_hwaddr[4], pkt->target_hwaddr[5]);
    plat_printf("  Target IP Address: %d.%d.%d.%d\n",
                pkt->target_addr[0], pkt->target_addr[1],
                pkt->target_addr[2], pkt->target_addr[3]);
}
#else
#define  display_arp_entity(entity)
#define  display_arp_tbl()
#define  display_arp_pkt(pkt)
#endif

// 释放缓存项中的等待发送的包
static void cache_cleanup(arp_entity_t* entity)
{
    // 释放等待发送的包
    nlist_node_t* node;
    while ((node = nlist_remove_first(&entity->buf_list)) != NULL)
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

// 发送缓存项中等待发送的所有包
static net_err_t cache_entity_send_all(arp_entity_t* entity)
{
    nlist_node_t* node;
    while ((node = nlist_remove_first(&entity->buf_list)) != NULL)
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        net_err_t err = ether_raw_out(entity->netif, PROTOCOL_TYPE_IPv4, entity->hwaddr, buf);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_ARP, "cache_entity_send_all: ether_raw_out fail, err=%d", err);
            pktbuf_free(buf);
            return err;
        }
    }
    return NET_ERR_OK;
}

// 分配一个ARP缓存项，force为1时，强制分配（释放最旧的缓存项）
static arp_entity_t* cache_alloc(const int force)
{
    arp_entity_t* entity = (arp_entity_t*)mblock_alloc(&cache_block, -1);
    if (entity == NULL && force)
    {
        // 强制分配时，释放掉最旧的缓存项
        nlist_node_t* node = nlist_remove_last(&cache_list);
        if (node == NULL)
        {
            dbug_error(DBG_MOD_ARP, "cache_alloc: no free arp entity");
            return NULL;
        }
        entity = nlist_entry(node, arp_entity_t, node);
        cache_cleanup(entity);
    }

    if (entity != NULL)
    {
        // 重置缓存项
        plat_memset(entity, 0, sizeof(arp_entity_t));
        entity->state = NET_ARP_FREE;

        // 初始化链表结点
        nlist_node_init(&entity->node);
        nlist_init(&entity->buf_list);
    }
    return entity;
}

// 释放ARP缓存项
static void cache_free(arp_entity_t* entity)
{
    if (entity == NULL)
    {
        return;
    }
    cache_cleanup(entity);
    nlist_remove(&cache_list, &entity->node);
    mblock_free(&cache_block, entity);
}

static arp_entity_t* cache_find(const uint8_t* ip)
{
    nlist_node_t* node;
    nlist_for_each(node, &cache_list)
    {
        arp_entity_t* entity = nlist_entry(node, arp_entity_t, node);
        if (plat_memcmp(entity->p_addr, ip, IPV4_ADDR_LEN) == 0)
        {
            return entity;
        }
    }
    return NULL;
}

const uint8_t* arp_find(const netif_t* netif, const ipaddr_t* addr)
{
    // 是否是本机IP地址
    if (addr->q_addr == netif->ipaddr.q_addr)
    {
        return netif->hwaddr.addr;
    }

    // 是否是广播地址
    if (is_local_broadcast_ip(addr) || is_directed_broadcast_ip(&netif->netmask, addr))
    {
        return ether_broadcast_addr();
    }

    // 查找ARP缓存
    uint8_t ip_buffer[IPV4_ADDR_LEN];
    ipaddr_to_buf(addr, ip_buffer);

    arp_entity_t* entity = cache_find(ip_buffer);
    if (entity != NULL && entity->state == NET_ARP_RESOLVE)
    {
        return entity->hwaddr;
    }

    return NULL;
}

static void cache_entity_set(arp_entity_t* entity, const uint8_t* hwaddr, const uint8_t* ip, netif_t* netif,
                             const int state)
{
    plat_memcpy(entity->hwaddr, hwaddr, ETHER_HWADDR_LEN);
    plat_memcpy(entity->p_addr, ip, IPV4_ADDR_LEN);
    entity->netif = netif;
    entity->state = state;
    switch (state)
    {
    case NET_ARP_RESOLVE:
        entity->timeout = to_scan_cnt(ARP_ENTRY_STABLE_TMO);
        break;
    case NET_ARP_WAITING:
        entity->timeout = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
        break;
    default:
        break;
    }
    entity->retry_cnt = ARP_MAX_RETRY_COUNT;
}

static net_err_t cache_insert(netif_t* netif, const uint8_t* ip, const uint8_t* hwaddr, const int force)
{
    if (*(uint32_t*)ip == 0)
    {
        return NET_ERR_INVALID_PARAM;
    }
    arp_entity_t* entity = cache_find(ip);
    if (entity == NULL)
    {
        entity = cache_alloc(force);
        if (entity == NULL)
        {
            dbug_error(DBG_MOD_ARP, "cache_insert: cache_alloc fail,ip:%s", ip);
            return NET_ERR_MEM;
        }
        cache_entity_set(entity, hwaddr, ip, netif, NET_ARP_RESOLVE);
        nlist_insert_first(&cache_list, &entity->node);
    }
    else
    {
        cache_entity_set(entity, hwaddr, ip, netif, NET_ARP_RESOLVE);

        // 挪到链表头部，表示最近使用过
        if (nlist_first(&cache_list) != &entity->node)
        {
            nlist_remove(&cache_list, &entity->node);
            nlist_insert_first(&cache_list, &entity->node);
        }

        net_err_t err = cache_entity_send_all(entity);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_ARP, "cache_insert: cache_entity_send_all fail, ip:%s", ip);
            return err;
        }
    }

    display_arp_tbl();
    return NET_ERR_OK;
}

static void arp_cache_tmo(net_timer_t* timer, void* arg)
{
    int change_cnt = 0;
    nlist_node_t* next;
    for (nlist_node_t* curr = cache_list.first; curr != NULL; curr = next)
    {
        next = nlist_node_next(curr);

        arp_entity_t* entity = nlist_entry(curr, arp_entity_t, node);

        if (--entity->timeout > 0) // 未超时
        {
            continue;
        }
        change_cnt++;
        ipaddr_t addr;
        ipaddr_from_buf(&addr, entity->p_addr);
        switch (entity->state)
        {
        case NET_ARP_WAITING:
            dbug_info(DBG_MOD_ARP, "state NET_ARP_WAITING");
            if (--entity->retry_cnt <= 0)
            {
                dbug_info(DBG_MOD_ARP, "ARP解析超时，释放缓存项");
                cache_free(entity);
                break;
            }
            // 重试发送ARP请求
            entity->timeout = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
            arp_make_request(entity->netif, &addr);
            break;
        case NET_ARP_RESOLVE:
            dbug_info(DBG_MOD_ARP, "state NET_ARP_RESOLVE");
            entity->state = NET_ARP_WAITING;
            entity->timeout = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
            entity->retry_cnt = ARP_MAX_RETRY_COUNT;
            arp_make_request(entity->netif, &addr);
            break;
        default:
            break;
        }
    }

    if (change_cnt > 0)
    {
        dbug_info(DBG_MOD_ARP, "%d arp entity change_cnt", change_cnt);
        display_arp_tbl();
    }
}

static net_err_t cache_init()
{
    nlist_init(&cache_list);

    net_err_t err = mblock_init(&cache_block, &cache_tbl, sizeof(arp_entity_t), ARP_CACHE_SIZE, NLOCKER_TYPE_NONE);
    if (err != NET_ERR_OK)
    {
        return err;
    }

    // 启动ARP缓存定时器
    err = net_timer_add(&cache_timer, "arp timer", arp_cache_tmo, NULL, ARP_TIMER_TMO * 1000, TIMER_FLAG_PERIODIC);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ARP, "cache_init: net_timer_add fail, err=%d", err);
        return err;
    }
    return NET_ERR_OK;
}

net_err_t arp_init()
{
    net_err_t err = cache_init();
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ARP, "");
        return err;
    }
    return NET_ERR_OK;
}

net_err_t arp_make_request(netif_t* netif, const ipaddr_t* addr)
{
    pktbuf_t* buf = pktbuf_alloc(sizeof(arp_pkt_t));
    if (buf == NULL)
    {
        dbug_error(DBG_MOD_ARP, "pktbuf_alloc fail");
        return NET_ERR_MEM;
    }

    pktbuf_set_cont(buf, sizeof(arp_pkt_t));

    arp_pkt_t* arp_pkt = (arp_pkt_t*)pktbuf_data(buf);
    arp_pkt->h_type = x_htons(ARP_HW_ETHER);
    arp_pkt->p_type = x_htons(PROTOCOL_TYPE_IPv4);
    arp_pkt->hw_len = ETHER_HWADDR_LEN;
    arp_pkt->p_len = IPV4_ADDR_LEN;
    arp_pkt->opcode = x_htons(ARP_REQUEST);
    plat_memcpy(arp_pkt->sender_hwaddr, netif->hwaddr.addr, ETHER_HWADDR_LEN);
    ipaddr_to_buf(&netif->ipaddr, arp_pkt->sender_addr);
    plat_memset(arp_pkt->target_hwaddr, 0, ETHER_HWADDR_LEN);
    ipaddr_to_buf(addr, arp_pkt->target_addr);

    display_arp_pkt(arp_pkt);

    net_err_t err = ether_raw_out(netif, PROTOCOL_TYPE_ARP, ether_broadcast_addr(), buf);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ARP, "ether_raw_out fail");
        pktbuf_free(buf);
        return err;
    }

    return NET_ERR_OK;
}

net_err_t arp_make_gratuitous_request(netif_t* netif)
{
    return arp_make_request(netif, &netif->ipaddr);
}

net_err_t arp_pkt_is_valid(const netif_t* netif, const arp_pkt_t* arp_pkt, const int size)
{
    // 包大小检查
    if (size < (int)sizeof(arp_pkt_t))
    {
        dbug_warn(DBG_MOD_ARP, "arp_pkt_is_valid: invalid arp packet size");
        return NET_ERR_FRAME;
    }
    // 硬件类型、协议类型、地址长度检查
    if (x_ntohs(arp_pkt->h_type) != ARP_HW_ETHER ||
        x_ntohs(arp_pkt->p_type) != PROTOCOL_TYPE_IPv4 ||
        arp_pkt->hw_len != ETHER_HWADDR_LEN ||
        arp_pkt->p_len != IPV4_ADDR_LEN)
    {
        dbug_warn(DBG_MOD_ARP, "arp_pkt_is_valid: invalid arp packet fields");
        return NET_ERR_FRAME;
    }

    uint16_t opcode = x_ntohs(arp_pkt->opcode);
    // 操作码检查
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY)
    {
        dbug_warn(DBG_MOD_ARP, "arp_pkt_is_valid: invalid arp opcode");
        return NET_ERR_FRAME;
    }

    // 目标IP地址检查，必须是发给本机的ARP请求或应答
    // if (plat_memcmp(arp_pkt->target_addr, netif->ipaddr.a_addr, IPV4_ADDR_LEN) != 0)
    // {
    //     dbug_warn(DBG_MOD_ARP, "ARP 目标地址不匹配");
    //     return NET_ERR_TARGET_ADDR_MATCH;
    // }
    return NET_ERR_OK;
}

net_err_t arp_in(netif_t* netif, pktbuf_t* buf)
{
    net_err_t err = NET_ERR_OK;
    // 确保包是连续的
    if ((err = pktbuf_set_cont(buf, sizeof(arp_pkt_t))) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ARP, "arp_in: pktbuf_set_cont failed, err=%d", err);
        return err;
    }

    arp_pkt_t* arp_pkt = (arp_pkt_t*)pktbuf_data(buf);
    err = arp_pkt_is_valid(netif, arp_pkt, pktbuf_total(buf));
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ARP, "arp_in: invalid arp packet, err=%d", err);
        return err;
    }

    uint16_t opcode = x_ntohs(arp_pkt->opcode);
    // 操作码检查
    switch (opcode)
    {
    case ARP_REQUEST:
    case ARP_REPLY:
        display_arp_pkt(arp_pkt);

        ipaddr_t target_ip;
        ipaddr_set_any(&target_ip);
        ipaddr_from_buf(&target_ip, arp_pkt->target_addr);
        if (ipaddr_is_equal(&netif->ipaddr, &target_ip))
        {
            // 更新ARP缓存
            cache_insert(netif, arp_pkt->sender_addr, arp_pkt->sender_hwaddr, 1);

            // 如果是ARP请求，发送ARP应答
            if (opcode == ARP_REQUEST)
            {
                return arp_make_reply(netif, buf);
            }
        }
        else
        {
            // 更新ARP缓存
            cache_insert(netif, arp_pkt->sender_addr, arp_pkt->sender_hwaddr, 0);
        }
        break;
    default:
        dbug_warn(DBG_MOD_ARP, "arp_in: unknown arp opcode %d", opcode);
        return NET_ERR_FRAME;
    }

    pktbuf_free(buf);
    return NET_ERR_OK;
}

net_err_t arp_make_reply(netif_t* netif, pktbuf_t* buf)
{
    arp_pkt_t* arp_pkt = (arp_pkt_t*)pktbuf_data(buf);
    arp_pkt->opcode = x_htons(ARP_REPLY);
    // 接收方MAC地址变为发送方MAC地址
    plat_memcpy(arp_pkt->target_hwaddr, arp_pkt->sender_hwaddr, ETHER_HWADDR_LEN);
    // 发送方MAC地址变为本机MAC地址
    plat_memcpy(arp_pkt->sender_hwaddr, netif->hwaddr.addr, ETHER_HWADDR_LEN);
    // 交换IP地址
    plat_memcpy(arp_pkt->target_addr, arp_pkt->sender_addr, IPV4_ADDR_LEN);
    // 本机IP地址变为发送方IP地址
    ipaddr_to_buf(&netif->ipaddr, arp_pkt->sender_addr);

    display_arp_pkt(arp_pkt);

    return ether_raw_out(netif, PROTOCOL_TYPE_ARP, arp_pkt->target_hwaddr, buf);
}

net_err_t arp_resolve(netif_t* netif, const ipaddr_t* addr, pktbuf_t* buf)
{
    uint8_t ip_buffer[IPV4_ADDR_LEN];
    ipaddr_to_buf(addr, ip_buffer);

    arp_entity_t* entity = cache_find(ip_buffer);
    if (entity != NULL)
    {
        if (entity->state == NET_ARP_RESOLVE) // 已解析，直接发送
        {
            return ether_raw_out(netif, PROTOCOL_TYPE_IPv4, entity->hwaddr, buf);
        }

        // 未解析，加入等待发送队列

        // 等待队列是否已满
        if (nlist_count(&entity->buf_list) >= ARP_MAX_PKT_WAITING)
        {
            dbug_warn(DBG_MOD_ARP, "arp_resolve: waiting queue full");
            pktbuf_free(buf);
            return NET_ERR_FULL;
        }
        // 加入等待发送队列
        nlist_insert_last(&entity->buf_list, &buf->node);
        return NET_ERR_OK;
    }


    // 分配一个新的缓存项
    entity = cache_alloc(1);
    if (entity == NULL)
    {
        dbug_error(DBG_MOD_ARP, "arp_resolve: cache_alloc fail");
        pktbuf_free(buf);
        return NET_ERR_MEM;
    }

    cache_entity_set(entity, empty_hwaddr, ip_buffer, netif, NET_ARP_WAITING);

    // 加入等待发送队列
    nlist_init(&entity->buf_list);
    nlist_insert_last(&entity->buf_list, &buf->node);
    nlist_insert_first(&cache_list, &entity->node);

    // 发送ARP请求
    return arp_make_request(netif, addr);
}

void arp_clear(const netif_t* netif)
{
    nlist_node_t* next;
    for (nlist_node_t* curr = cache_list.first; curr != NULL; curr = next)
    {
        next = nlist_node_next(curr);

        arp_entity_t* entity = nlist_entry(curr, arp_entity_t, node);
        if (entity->netif == netif)
        {
            cache_free(entity);
            // nlist_remove(&cache_list, curr);
        }
    }
}

void arp_update_from_ip_buf(netif_t* netif,  pktbuf_t* buf)
{
    // 确保包是连续的
    net_err_t err = pktbuf_set_cont(buf, sizeof(ether_header_t) + sizeof(ipv4_header_t));
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_ARP, "arp_update_from_ip_buf: pktbuf_set_cont failed, err=%d", err);
        return;
    }

    ether_header_t* eth_hdr = (ether_header_t*)pktbuf_data(buf);
    ipv4_header_t* ip_hdr = (ipv4_header_t*)((uint8_t*)eth_hdr + sizeof(ether_header_t));

    if (ip_hdr->version != NET_VERSION_IPV4)
    {
        dbug_warn(DBG_MOD_ARP, "arp_update_from_ip_buf: not ipv4 packet");
        return;
    }

    uint8_t src_ip[IPV4_ADDR_LEN];
    plat_memcpy(src_ip, &ip_hdr->src_addr, IPV4_ADDR_LEN);

    cache_insert(netif, src_ip, eth_hdr->src_mac, 0);
}
