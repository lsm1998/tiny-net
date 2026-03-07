#include "ipv4.h"
#include "dbug.h"
#include "protocol.h"
#include "tool.h"
#include "icmp_v4.h"
#include "mblock.h"
#include "raw.h"
#include "udp.h"
#include "tcp_in.h"

static uint16_t packet_id = 0;

static ip_fragment_t fragments[IPV4_FRAGS_MAX_NR];

static mblock_t fragment_mblock;

static nlist_t fragment_list;

static nlist_t route_list;

static route_entry_t route_table[IPV4_ROUTE_TABLE_MAX_NR];

static mblock_t route_table_mblock;

static net_err_t fragment_init()
{
    nlist_init(&fragment_list);
    net_err_t err = mblock_init(&fragment_mblock, fragments, sizeof(ip_fragment_t), IPV4_FRAGS_MAX_NR,
                                NLOCKER_TYPE_NONE);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_IPV4, "fragment_init: mblock_init failed, err=%d", err);
        return err;
    }
    return NET_ERR_OK;
}

static void fragment_free_buf_list(ip_fragment_t* frag)
{
    nlist_node_t* node;
    while ((node = nlist_remove_first(&frag->buf_list)) != NULL)
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

static ip_fragment_t* fragment_alloc()
{
    ip_fragment_t* frag = mblock_alloc(&fragment_mblock, -1);
    if (frag == NULL)
    {
        // 移除最旧的分片
        nlist_node_t* node = nlist_remove_first(&fragment_list);
        frag = nlist_entry(node, ip_fragment_t, node);
        if (frag != NULL)
        {
            fragment_free_buf_list(frag);
        }
    }
    return frag;
}

static void fragment_free(ip_fragment_t* frag)
{
    if (frag != NULL)
    {
        fragment_free_buf_list(frag);
        nlist_remove(&fragment_list, &frag->node);
        mblock_free(&fragment_mblock, frag);
    }
}

static void fragment_add(ip_fragment_t* frag, const ipaddr_t* ip, const uint16_t id)
{
    frag->id = id;
    frag->tmo = 0;
    ipaddr_copy(&frag->ip, ip);
    nlist_node_init(&frag->node);
    nlist_init(&frag->buf_list);
    nlist_insert_first(&fragment_list, &frag->node);
}

static ip_fragment_t* fragment_find(const ipaddr_t* ip, const uint16_t id)
{
    nlist_node_t* node;
    nlist_for_each(node, &fragment_list)
    {
        ip_fragment_t* frag = nlist_entry(node, ip_fragment_t, node);
        if (frag->id == id && ipaddr_is_equal(&frag->ip, ip))
        {
            nlist_remove(&fragment_list, &frag->node);
            nlist_insert_last(&fragment_list, &frag->node);
            return frag;
        }
    }
    return NULL;
}

static uint16_t get_fragment_data_size(const ipv4_pkt_t* pkt)
{
    return pkt->header.total_len - ipv4_hdr_size(pkt);
}

static uint16_t get_fragment_start(const ipv4_pkt_t* pkt)
{
    return pkt->header.frag_offset * 8;
}

static uint16_t get_fragment_end(const ipv4_pkt_t* pkt)
{
    return get_fragment_start(pkt) + get_fragment_data_size(pkt);
}

#if DBG_DISPLAY_ENABLE(DBG_MOD_IPV4)
static void display_ipv4_header(const ipv4_pkt_t* pkt)
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_IPV4)) return;

    const ipv4_header_t* hdr = &pkt->header;
    plat_printf("IPv4 Header:\n");
    plat_printf("  Version: %u\n", hdr->version);
    plat_printf("  Header Length: %u bytes\n", hdr->shdr * 4);
    plat_printf("  Type of Service: 0x%02X\n", hdr->tos);
    plat_printf("  Total Length: %u bytes\n", x_ntohs(hdr->total_len));
    plat_printf("  Identification: 0x%04X\n", x_ntohs(hdr->id));
    plat_printf("  Flags and Fragment Offset: 0x%04X\n", x_ntohs(hdr->frag_offset));
    plat_printf("  More Fragments: %s\n", hdr->more_frags ? "Yes" : "No");
    plat_printf("  Time to Live: %u\n", hdr->ttl);
    plat_printf("  Protocol: %u\n", hdr->protocol);
    plat_printf("  Header Checksum: 0x%04X\n", x_ntohs(hdr->header_checksum));
    plat_printf("  Source Address: %u.%u.%u.%u\n",
                hdr->src_addr[0], hdr->src_addr[1], hdr->src_addr[2], hdr->src_addr[3]);
    plat_printf("  Destination Address: %u.%u.%u.%u\n",
                hdr->dest_addr[0], hdr->dest_addr[1], hdr->dest_addr[2], hdr->dest_addr[3]);
}

static void display_ipv4_fragment()
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_IPV4)) return;

    nlist_node_t* node;
    int index = 0;
    nlist_for_each(node, &fragment_list)
    {
        ip_fragment_t* frag = nlist_entry(node, ip_fragment_t, node);

        plat_printf("IPv4 Fragment: index: %d\n", index++);
        plat_printf("  ID: 0x%04X\n", frag->id);
        plat_printf("  Ip: \n");
        dbug_dump_ipaddr(&frag->ip);
        plat_printf("  Timeout: %d\n", frag->tmo);
        plat_printf("  Buffers:%d\n", nlist_count(&frag->buf_list));
        nlist_node_t* buf_node;
        int buf_index = 0;
        nlist_for_each(buf_node, &frag->buf_list)
        {
            pktbuf_t* buf = nlist_entry(buf_node, pktbuf_t, node);
            ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
            plat_printf("    Buffer %d: [%d-%d]\n",
                        buf_index++, get_fragment_start(pkt), get_fragment_end(pkt) - 1);
        }
        plat_printf("\n");
    }
}

static void display_ipv4_route_table()
{
    if (!DBG_DISPLAY_CHECK(DBG_MOD_IPV4)) return;

    plat_printf("IPv4 Route Table:\n");
    plat_printf("  %-15s %-15s %-15s %-10s\n", "Destination", "Netmask", "Gateway", "Netif");
    for (int i = 0; i < IPV4_ROUTE_TABLE_MAX_NR; i++)
    {
        route_entry_t* entry = &route_table[i];
        if (entry->netif == NULL)
        {
            continue;
        }
        char dest_str[16];
        char netmask_str[16];
        char next_hop_str[16];

        ipaddr_to_str(&entry->net, dest_str, sizeof(dest_str));
        ipaddr_to_str(&entry->mask, netmask_str, sizeof(netmask_str));
        ipaddr_to_str(&entry->next_hop, next_hop_str, sizeof(next_hop_str));

        plat_printf("  %-15s %-15s %-15s %-10s\n",
                    dest_str,
                    netmask_str,
                    next_hop_str,
                    entry->netif->name);
    }
    plat_printf("\n");
}
#else
#define  display_ipv4_header(header)
#define display_ipv4_fragment()
#define display_ipv4_route_table()
#endif

static void ipv4_header_ntohs(ipv4_header_t* hdr)
{
    hdr->total_len = x_ntohs(hdr->total_len);
    hdr->id = x_ntohs(hdr->id);
    hdr->frag_all = x_ntohs(hdr->frag_all);
    hdr->header_checksum = x_ntohs(hdr->header_checksum);
}

static void ipv4_header_htonl(ipv4_header_t* hdr)
{
    hdr->total_len = x_htons(hdr->total_len);
    hdr->id = x_htons(hdr->id);
    hdr->frag_all = x_htons(hdr->frag_all);
    hdr->header_checksum = x_htons(hdr->header_checksum);
}


// 所有分片是否齐全
static bool fragment_is_all_arrived(const ip_fragment_t* fragment)
{
    int offset = 0;
    nlist_node_t* node;
    nlist_for_each(node, &fragment->buf_list)
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
        int start = get_fragment_start(pkt);
        if (start != offset)
        {
            return false;
        }
        offset += get_fragment_data_size(pkt);
        if (!pkt->header.more_frags)
        {
            return true;
        }
    }
    return false;
}

static pktbuf_t* fragment_join(ip_fragment_t* fragment)
{
    pktbuf_t* joined_buf = NULL;
    nlist_node_t* node;
    while ((node = nlist_remove_first(&fragment->buf_list)) != NULL)
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        if (joined_buf == NULL)
        {
            joined_buf = buf;
            continue;
        }
        ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
        net_err_t err = pktbuf_remove_header(buf, ipv4_hdr_size(pkt));
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_IPV4, "fragment_join: pktbuf_remove_header failed, err=%d", err);
            pktbuf_free(buf);
            goto err_return;
        }
        err = join_pktbuf(joined_buf, buf);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_IPV4, "fragment_join: join_pktbuf failed, err=%d", err);
            pktbuf_free(buf);
            goto err_return;
        }
    }

    return joined_buf;

err_return:
    pktbuf_free(joined_buf);
    fragment_free(fragment);
    return NULL;
}

static net_err_t ipv4_pkt_is_valid(const ipv4_pkt_t* pkt, const uint32_t size, netif_t* netif)
{
    // 检查版本号
    if (pkt->header.version != NET_VERSION_IPV4)
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_pkt_is_valid: invalid version %d", pkt->header.version);
        return NET_ERR_FRAME;
    }

    int hdr_len = ipv4_hdr_size(pkt);
    if (hdr_len < sizeof(ipv4_header_t))
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_pkt_is_valid: invalid header length %d", hdr_len);
        return NET_ERR_FRAME;
    }

    int total_len = x_ntohs(pkt->header.total_len);
    if (total_len < hdr_len || total_len > size)
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_pkt_is_valid: invalid total length %d", total_len);
        return NET_ERR_FRAME;
    }


    // 检查校验和
    if (pkt->header.header_checksum)
    {
        uint16_t checksum = checksum16(&pkt->header, hdr_len, 0, true);
        if (checksum != 0)
        {
            dbug_warn(DBG_MOD_IPV4, "ipv4_pkt_is_valid: invalid header checksum 0x%04X", checksum);
            return NET_ERR_CHECKSUM;
        }
    }

    return NET_ERR_OK;
}

static net_err_t ip_normal_input(const netif_t* netif, pktbuf_t* buf, const ipaddr_t* src_ip, const ipaddr_t* dest_ip)
{
    ipv4_pkt_t* ipv4_pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    display_ipv4_header(ipv4_pkt);
    net_err_t err = NET_ERR_OK;
    switch (ipv4_pkt->header.protocol)
    {
    case PROTOCOL_TYPE_ICMP_V4: // ICMP
        err = icmp_v4_input(src_ip, &netif->ipaddr, buf);
        break;
    case PROTOCOL_TYPE_UDP: // UDP
        err = udp_input(buf, src_ip, dest_ip);
        if (err == NET_ERR_PORT_UNREACH)
        {
            ipv4_header_ntohs(&ipv4_pkt->header);
            icmp_v4_output_unreach(src_ip, &netif->ipaddr, ICMP_V4_CODE_UNREACH_PORT, buf);
            return err;
        }
        break;
    case PROTOCOL_TYPE_TCP: // TCP
        pktbuf_remove_header(buf, ipv4_hdr_size(ipv4_pkt));

        err = tcp_input(buf, src_ip, dest_ip);
        break;
    default:
        err = raw_input(buf);
        break;
    }

    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_IPV4, "ip_normal_input: protocol %d input failed, err=%d", ipv4_pkt->header.protocol, err);
    }
    return err;
}

// 插入分片包
static net_err_t ip_fragment_insert(ip_fragment_t* fragment, pktbuf_t* buf, const ipv4_pkt_t* ipv4_pkt)
{
    if (nlist_count(&fragment->buf_list) >= IPV4_FRAGS_BUFFER_MAX_NR)
    {
        dbug_warn(DBG_MOD_IPV4, "ip_fragment_insert: fragment buffer list full");
        fragment_free(fragment);
        return NET_ERR_MEM;
    }

    // 插入分片
    nlist_node_t* node;
    nlist_for_each(node, &fragment->buf_list)
    {
        pktbuf_t* exist_buf = nlist_entry(node, pktbuf_t, node);
        ipv4_pkt_t* exist_pkt = (ipv4_pkt_t*)pktbuf_data(exist_buf);

        uint16_t exist_start = get_fragment_start(exist_pkt);
        uint16_t pkt_start = get_fragment_start(ipv4_pkt);
        uint16_t pkt_end = get_fragment_end(ipv4_pkt);

        if (pkt_start == exist_start)
        {
            return NET_ERR_EXIST;
        }

        if (pkt_end <= exist_start)
        {
            nlist_node_t* prev_node = nlist_node_prev(node);
            if (prev_node == NULL)
            {
                nlist_insert_first(&fragment->buf_list, &buf->node);
            }
            else
            {
                nlist_insert_after(&fragment->buf_list, prev_node, &buf->node);
            }
            return NET_ERR_OK;
        }
    }
    nlist_insert_last(&fragment->buf_list, &buf->node);
    return NET_ERR_OK;
}

// 处理分片包输入
static net_err_t ip_fragment_input(netif_t* netif, pktbuf_t* buf, const ipaddr_t* src_ip, const ipaddr_t* dest_ip,
                                   bool* buf_consumed)
{
    *buf_consumed = false;
    ipv4_pkt_t* ipv4_pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    ip_fragment_t* frag = fragment_find(src_ip, ipv4_pkt->header.id);
    if (frag == NULL)
    {
        frag = fragment_alloc();
        if (frag == NULL)
        {
            dbug_error(DBG_MOD_IPV4, "ip_fragment_input: fragment_alloc failed");
            return NET_ERR_MEM;
        }
        fragment_add(frag, src_ip, ipv4_pkt->header.id);
    }

    net_err_t err = ip_fragment_insert(frag, buf, ipv4_pkt);
    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_IPV4, "ip_fragment_input: ip_fragment_insert failed, err=%d", err);
        return err;
    }

    *buf_consumed = true;

    // 是否所有分片到达
    if (fragment_is_all_arrived(frag))
    {
        pktbuf_t* joined_buf = fragment_join(frag);
        if (joined_buf == NULL)
        {
            dbug_error(DBG_MOD_IPV4, "ip_fragment_input: fragment_join failed");
            return NET_ERR_MEM;
        }
        fragment_free(frag);
        err = ip_normal_input(netif, joined_buf, src_ip, dest_ip);
        if (err != NET_ERR_OK)
        {
            dbug_warn(DBG_MOD_IPV4, "ip_fragment_input: ip_normal_input failed, err=%d", err);
            pktbuf_free(joined_buf);
            return err;
        }
    }

    display_ipv4_fragment();
    return NET_ERR_OK;
}

int ipv4_hdr_size(const ipv4_pkt_t* pkt)
{
    return pkt->header.shdr * 4;
}

void ipv4_set_hdr_size(ipv4_pkt_t* pkt, const int size)
{
    pkt->header.shdr = size / 4;
}

net_err_t ipv4_init()
{
    dbug_info(DBG_MOD_IPV4, "ipv4_init");
    net_err_t err = fragment_init();
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_IPV4, "ipv4_init: fragment_init failed, err=%d", err);
        return err;
    }

    route_entry_init();

    return NET_ERR_OK;
}

void route_entry_init()
{
    nlist_init(&route_list);

    mblock_init(&route_table_mblock, route_table, sizeof(route_entry_t), IPV4_ROUTE_TABLE_MAX_NR, NLOCKER_TYPE_NONE);
}


void route_entry_add(const ipaddr_t* net, const ipaddr_t* mask, const ipaddr_t* next_hop, netif_t* netif)
{
    route_entry_t* entry = mblock_alloc(&route_table_mblock, -1);
    if (entry == NULL)
    {
        dbug_error(DBG_MOD_IPV4, "route_entry_add: mblock_alloc failed");
        return;
    }

    ipaddr_copy(&entry->net, net);
    ipaddr_copy(&entry->mask, mask);
    ipaddr_copy(&entry->next_hop, next_hop);
    entry->netif = netif;
    entry->mask_1_cnt = ipaddr_1_count(mask);

    nlist_node_init(&entry->node);
    nlist_insert_last(&route_list, &entry->node);
    display_ipv4_route_table();
}

void route_entry_remove(const ipaddr_t* net, const ipaddr_t* mask)
{
    nlist_node_t* node;
    nlist_for_each(node, &route_list)
    {
        route_entry_t* entry = nlist_entry(node, route_entry_t, node);
        if (ipaddr_is_equal(&entry->net, net) && ipaddr_is_equal(&entry->mask, mask))
        {
            nlist_remove(&route_list, &entry->node);
            mblock_free(&route_table_mblock, entry);
            return;
        }
    }
    display_ipv4_route_table();
}

net_err_t ipv4_input(netif_t* netif, pktbuf_t* buf)
{
    dbug_info(DBG_MOD_IPV4, "ipv4_input");

    // 设置包的连续性
    pktbuf_set_cont(buf, sizeof(ipv4_header_t));

    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    // 验证ipv4包是否合法
    net_err_t err = ipv4_pkt_is_valid(pkt, buf->total_size, netif);
    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_input: invalid ipv4 packet, err=%d", err);
        return err;
    }

    ipv4_header_ntohs(&pkt->header);

    // 调整包的长度 为实际长度
    if ((err = pktbuf_resize(buf, pkt->header.total_len)) < 0)
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_input: pktbuf_resize failed, err=%d", err);
        return err;
    }

    ipaddr_t src_ip, dest_ip;
    ipaddr_from_buf(&src_ip, pkt->header.src_addr);
    ipaddr_from_buf(&dest_ip, pkt->header.dest_addr);

    if (!ipaddr_is_match(&dest_ip, &netif->ipaddr, &netif->netmask))
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_input: packet not for us,dest ip %s", dest_ip.a_addr);
        return NET_ERR_TARGET_ADDR_MATCH;
    }

    bool buf_consumed = false;

    // 是否为分片包
    if (pkt->header.frag_offset || pkt->header.more_frags)
    {
        err = ip_fragment_input(netif, buf, &src_ip, &dest_ip, &buf_consumed);
    }
    else
    {
        err = ip_normal_input(netif, buf, &src_ip, &dest_ip);
    }

    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_IPV4, "ipv4_input: ip_normal_input failed, err=%d", err);
        if (buf_consumed)
        {
            return NET_ERR_OK;
        }
        return err;
    }

    return NET_ERR_OK;
}

// 发送单个IP数据包
static net_err_t ipv4_send_pkt(netif_t* netif, const ipaddr_t* dest_ip, pktbuf_t* buf)
{
    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    // 转换为网络字节序
    ipv4_header_htonl(&pkt->header);

    // 重置访问位置并计算校验和
    pktbuf_reset_access(buf);
    pkt->header.header_checksum = pktbuf_checksum16(buf, ipv4_hdr_size(pkt), 0, true);

    display_ipv4_header(pkt);

    return netif_out(netif, (ipaddr_t*)dest_ip, buf);
}

// 分片发送
static net_err_t ipv4_output_fragment(netif_t* netif, const ipaddr_t* dest_ip, pktbuf_t* buf)
{
    // 保存原始IP头（主机字节序）
    ipv4_header_t orig_hdr;
    plat_memcpy(&orig_hdr, pktbuf_data(buf), sizeof(ipv4_header_t));

    int hdr_size = sizeof(ipv4_header_t);
    int data_total = (int)orig_hdr.total_len - hdr_size;
    // 每个分片的最大数据量，向下对齐8字节
    int max_data = (netif->mtu - hdr_size) & ~7;

    // 移除原始IP头，buf只保留载荷数据
    pktbuf_remove_header(buf, hdr_size);
    pktbuf_reset_access(buf);

    int offset = 0;
    net_err_t err = NET_ERR_OK;

    while (offset < data_total)
    {
        int remain = data_total - offset;
        int frag_data_size = (remain > max_data) ? max_data : remain;
        bool is_last = (offset + frag_data_size >= data_total);

        // 分配新的分片buf
        pktbuf_t* frag_buf = pktbuf_alloc(frag_data_size);
        if (!frag_buf)
        {
            dbug_error(DBG_MOD_IPV4, "ipv4_output_fragment: pktbuf_alloc failed");
            err = NET_ERR_MEM;
            break;
        }

        // 从原始buf的当前位置复制数据到分片buf
        pktbuf_reset_access(frag_buf);
        err = pktbuf_copy(frag_buf, buf, frag_data_size);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_IPV4, "ipv4_output_fragment: pktbuf_copy failed, err=%d", err);
            pktbuf_free(frag_buf);
            break;
        }

        // 添加IP头
        err = pktbuf_add_header(frag_buf, hdr_size, true);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_IPV4, "ipv4_output_fragment: pktbuf_add_header failed, err=%d", err);
            pktbuf_free(frag_buf);
            break;
        }

        // 复制原始头部，修改分片相关字段
        ipv4_pkt_t* frag_pkt = (ipv4_pkt_t*)pktbuf_data(frag_buf);
        plat_memcpy(&frag_pkt->header, &orig_hdr, hdr_size);
        frag_pkt->header.total_len = (uint16_t)(hdr_size + frag_data_size);
        frag_pkt->header.frag_offset = (uint16_t)(offset / 8);
        frag_pkt->header.more_frags = is_last ? 0 : 1;
        frag_pkt->header.header_checksum = 0;

        // 发送分片
        err = ipv4_send_pkt(netif, dest_ip, frag_buf);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_IPV4, "ipv4_output_fragment: send frag failed, offset=%d, err=%d", offset, err);
            pktbuf_free(frag_buf);
            break;
        }

        offset += frag_data_size;
    }

    // 成功时由分片发送路径消费原始buf；失败时仍交给上层按错误路径回收。
    if (err == NET_ERR_OK)
    {
        pktbuf_free(buf);
    }
    return err;
}

net_err_t ipv4_output(const uint8_t protocol, const ipaddr_t* dest_ip, const ipaddr_t* src_ip, pktbuf_t* buf)
{
    // 查找路由条目
    route_entry_t* route = find_route_entry(dest_ip);
    if (route == NULL)
    {
        dbug_error(DBG_MOD_IPV4, "ipv4_output: no route to host %s", dest_ip->a_addr);
        return NET_ERR_NO_ROUTE;
    }

    ipaddr_t next_hop_ip;
    if (ipaddr_is_any(&route->next_hop))
    {
        // 直连网络，下一跳为目的地址
        ipaddr_copy(&next_hop_ip, dest_ip);
    }
    else
    {
        // 非直连网络，下一跳为路由表中的下一跳地址
        ipaddr_copy(&next_hop_ip, &route->next_hop);
    }

    netif_t* netif = route->netif;

    // 添加IPv4头
    net_err_t err = pktbuf_add_header(buf, sizeof(ipv4_header_t), true);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_IPV4, "ipv4_output: pktbuf_add_header failed, err=%d", err);
        return err;
    }

    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    pkt->header.shar_all = 0;
    pkt->header.version = NET_VERSION_IPV4;
    ipv4_set_hdr_size(pkt, sizeof(ipv4_header_t));
    pkt->header.total_len = (uint16_t)buf->total_size;
    pkt->header.id = ++packet_id;
    pkt->header.frag_all = 0;
    pkt->header.ttl = 64;
    pkt->header.header_checksum = 0;
    pkt->header.protocol = protocol;
    if (src_ip == NULL || ipaddr_is_any(src_ip))
    {
        src_ip = &netif->ipaddr;
    }
    ipaddr_to_buf(src_ip, pkt->header.src_addr);
    ipaddr_to_buf(dest_ip, pkt->header.dest_addr);

    // 不需要分片，直接发送
    if ((int)buf->total_size <= netif->mtu)
    {
        return ipv4_send_pkt(netif, &next_hop_ip, buf);
    }

    // 需要分片发送
    dbug_info(DBG_MOD_IPV4, "ipv4_output: packet size %d > mtu %d, fragmenting", buf->total_size, netif->mtu);
    return ipv4_output_fragment(netif, &next_hop_ip, buf);
}

route_entry_t* find_route_entry(const ipaddr_t* dest_ip)
{
    route_entry_t* best_entry = NULL;
    nlist_node_t* node;
    nlist_for_each(node, &route_list)
    {
        route_entry_t* entry = nlist_entry(node, route_entry_t, node);

        ipaddr_t net = ipaddr_get_network(dest_ip, &entry->mask);
        if (!ipaddr_is_equal(&net, &entry->net))
        {
            continue;
        }
        if (best_entry == NULL || entry->mask_1_cnt > best_entry->mask_1_cnt)
        {
            best_entry = entry;
        }
    }
    return best_entry;
}
