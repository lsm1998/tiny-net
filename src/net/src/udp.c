#include "udp.h"
#include "dbug.h"
#include "mblock.h"
#include "socket.h"
#include "ipv4.h"
#include "tool.h"

static udp_t udp_tbl[UDP_MAX_NR];

static mblock_t udp_mblock;

static nlist_t udp_list;

static net_err_t alloc_port(sock_t* sock)
{
    for (uint16_t port = NET_PORT_DYN_START; port <= NET_PORT_DYN_END; ++port)
    {
        bool port_in_use = false;

        nlist_node_t* node;
        nlist_for_each(node, &udp_list)
        {
            udp_t* udp = nlist_entry(node, udp_t, base.node);
            if (udp->base.local_port == port)
            {
                port_in_use = true;
                break;
            }
        }

        if (!port_in_use)
        {
            sock->local_port = port;
            return NET_ERR_OK;
        }
    }

    return NET_ERR_FULL; // 没有可用端口
}

static net_err_t udp_pkt_invalid(const udp_pkt_t* pkt, const int size)
{
    if (size < (int)sizeof(udp_header_t))
    {
        return NET_ERR_FRAME;
    }

    uint16_t udp_len = pkt->header.length;
    if (udp_len < sizeof(udp_header_t) || udp_len > (uint16_t)size)
    {
        return NET_ERR_FRAME;
    }
    return NET_ERR_OK;
}

net_err_t upd_init()
{
    plat_memset(udp_tbl, 0, sizeof(udp_tbl));

    nlist_init(&udp_list);

    mblock_init(&udp_mblock, udp_tbl, sizeof(udp_t), UDP_MAX_NR, NLOCKER_TYPE_NONE);

    dbug_info(DBG_MOD_UDP, "init udp");
    return NET_ERR_OK;
}

net_err_t udp_sendto(sock_t* sock, const uint8_t* buf, const size_t len, int flags,
                     const struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t* sent_size)
{
    ipaddr_t dest_ip;

    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);

    uint16_t dest_port = x_ntohs(addr->sin_port);
    if (sock->remote_port != 0 && sock->remote_port != dest_port)
    {
        dbug_error(DBG_MOD_UDP, "raw_sendto: destination port mismatch");
        return NET_ERR_INVALID_PARAM;
    }

    // 分配端口
    if (sock->local_port == 0)
    {
        net_err_t err = alloc_port(sock);
        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_UDP, "raw_sendto: get free udp port failed");
            return err;
        }
    }

    if (!ipaddr_is_any(&sock->remote_ip) && !ipaddr_is_equal(&dest_ip, &sock->remote_ip))
    {
        dbug_error(DBG_MOD_UDP, "raw_sendto: destination address is any");
        return NET_ERR_INVALID_PARAM;
    }

    pktbuf_t* pktbuf = pktbuf_alloc((int)len);
    if (pktbuf == NULL)
    {
        dbug_error(DBG_MOD_UDP, "raw_sendto: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }

    net_err_t err = pktbuf_write(pktbuf, buf, (int)len);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "raw_sendto: pktbuf_write failed, err=%d", err);
        pktbuf_free(pktbuf);
        return err;
    }

    ipaddr_t src_ip;
    if (ipaddr_is_any(&sock->local_ip))
    {
        src_ip = netif_get_default()->ipaddr;
    }
    else
    {
        src_ip = sock->local_ip;
    }

    err = upd_output(&dest_ip, dest_port, &src_ip, sock->local_port, pktbuf);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "raw_sendto: ipv4_output failed, err=%d", err);
        pktbuf_free(pktbuf);
        return err;
    }
    *sent_size = (ssize_t)len;
    return NET_ERR_OK;
}

net_err_t udp_recvfrom(sock_t* sock, uint8_t* buf, const size_t len, int flags,
                       const struct x_sockaddr* src, x_socklen_t* src_len, ssize_t* recv_size)
{
    udp_t* udp = (udp_t*)sock;
    nlist_node_t* frist = nlist_remove_first(&udp->recv_list);
    if (frist == NULL)
    {
        *recv_size = 0;
        return NET_ERR_NEED_WAIT;
    }
    pktbuf_t* pktbuf = nlist_entry(frist, pktbuf_t, node);

    udp_from_t* from = (udp_from_t*)pktbuf_data(pktbuf);

    if (src != NULL)
    {
        struct x_sockaddr_in* addr = (struct x_sockaddr_in*)src;
        plat_memset(addr, 0, sizeof(struct x_sockaddr_in));
        addr->sin_len = sizeof(struct x_sockaddr_in);
        addr->sin_family = AF_INET;
        addr->sin_port = x_htons(from->src_port);
        ipaddr_to_buf(&from->src_ip, addr->sin_addr.addr_array);
    }
    if (src_len != NULL)
    {
        *src_len = sizeof(struct x_sockaddr_in);
    }

    pktbuf_remove_header(pktbuf, sizeof(udp_from_t));

    size_t copy_size = pktbuf->total_size < len ? pktbuf->total_size : len;
    pktbuf_reset_access(pktbuf);
    net_err_t err = pktbuf_read(pktbuf, buf, (int)copy_size);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "udp_recvfrom: pktbuf_read failed, err=%d", err);
        pktbuf_free(pktbuf);
        return err;
    }
    pktbuf_free(pktbuf);
    *recv_size = (ssize_t)copy_size;
    return NET_ERR_OK;
}

static net_err_t udp_close(sock_t* sock)
{
    udp_t* udp = (udp_t*)sock;

    // 从全局列表中移除
    nlist_remove(&udp_list, &udp->base.node);

    // 移除消息队列中的数据包
    nlist_node_t* node;
    while ((node = nlist_remove_first(&udp->recv_list)) != NULL)
    {
        pktbuf_t* pktbuf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(pktbuf);
    }

    // 释放sock
    sock_free(sock);

    // 释放udp内存块
    mblock_free(&udp_mblock, udp);
    return NET_ERR_OK;
}

static net_err_t udp_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addr_len)
{
    if (sock->local_port != 0)
    {
        dbug_error(DBG_MOD_UDP, "udp_bind: socket already bound");
        return NET_ERR_INVALID_STATE;
    }

    struct x_sockaddr_in* bind_addr = (struct x_sockaddr_in*)addr;
    ipaddr_t local_ip;
    ipaddr_from_buf(&local_ip, bind_addr->sin_addr.addr_array);
    uint16_t local_port = x_ntohs(bind_addr->sin_port);

    nlist_node_t* node;
    udp_t* udp = NULL;
    nlist_for_each(node, &udp_list)
    {
        udp_t* u = nlist_entry(node, udp_t, base.node);
        if (sock == &u->base)
        {
            continue; // 跳过当前socket
        }
        if (u->base.local_port == local_port)
        {
            udp = u;
            break;
        }
    }
    if (udp != NULL)
    {
        dbug_error(DBG_MOD_UDP, "udp_bind: address already in use");
        return NET_ERR_ADDR_IN_USE;
    }

    return sock_bind(sock, addr, addr_len);
}

sock_t* udp_create(const int family, const int protocol)
{
    static const sock_ops_t udp_ops = {
        .sendto = udp_sendto,
        .recvfrom = udp_recvfrom,
        .setopt = sock_setopt,
        .close = udp_close,
        .connect = sock_connect,
        .send = sock_send,
        .recv = sock_recv,
        .bind = udp_bind,
    };
    udp_t* udp = mblock_alloc(&udp_mblock, -1);
    if (udp == NULL)
    {
        dbug_error(DBG_MOD_UDP, "udp_create: no memory for udp");
        return NULL;
    }

    net_err_t err = sock_init(&udp->base, family, protocol, &udp_ops);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "udp_create: sock_init failed");
        goto create_fail;
    }

    udp->base.recv_wait = &udp->recv_wait;
    if ((err = sock_wait_init(&udp->recv_wait)) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "udp_create: sock_wait_init failed,err:%d", err);
        goto create_fail;
    }

    nlist_insert_last(&udp_list, &udp->base.node);
    nlist_init(&udp->recv_list);

    return &udp->base;

create_fail:
    sock_free(&udp->base);
    mblock_free(&udp_mblock, udp);
    return NULL;
}

net_err_t upd_output(const ipaddr_t* dest_ip, const uint16_t dest_port, const ipaddr_t* src_ip, const uint16_t src_port,
                     pktbuf_t* buf)
{
    net_err_t err = pktbuf_add_header(buf, sizeof(udp_header_t), true);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "upd_output: pktbuf_add_header failed, err=%d", err);
        return err;
    }
    udp_header_t* udp_hdr = (udp_header_t*)pktbuf_data(buf);
    udp_hdr->src_port = x_htons(src_port);
    udp_hdr->dest_port = x_htons(dest_port);
    udp_hdr->length = x_htons(buf->total_size);
    udp_hdr->checksum = 0;
    udp_hdr->checksum = checksum16_pseudo(buf, src_ip, dest_ip, IPPROTO_UDP);

    err = ipv4_output(IPPROTO_UDP, dest_ip, src_ip, buf);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "upd_output: ipv4_output failed, err=%d", err);
        return err;
    }
    return NET_ERR_OK;
}

static udp_t* udp_find(const ipaddr_t* src_ip, const uint16_t src_port, const ipaddr_t* dest_ip,
                       const uint16_t dest_port, bool* weak_match_used)
{
    if (weak_match_used)
    {
        *weak_match_used = false;
    }
    udp_t* weak_match = NULL;

    nlist_node_t* node;
    nlist_for_each(node, &udp_list)
    {
        udp_t* udp = nlist_entry(node, udp_t, base.node);

        if (udp->base.local_port != dest_port)
        {
            continue;
        }

        if (!ipaddr_is_any(&udp->base.local_ip) && !ipaddr_is_equal(&udp->base.local_ip, dest_ip))
        {
            continue;
        }

        bool remote_ip_match = ipaddr_is_any(&udp->base.remote_ip) || ipaddr_is_equal(&udp->base.remote_ip, src_ip);
        bool remote_port_match = (udp->base.remote_port == 0 || udp->base.remote_port == src_port);
        if (remote_ip_match && remote_port_match)
        {
            return udp;
        }

        // 某些场景下，回包源IP会被网关/NAT改写；在本地端口唯一时，允许降级匹配
        if (!remote_ip_match && remote_port_match && weak_match == NULL)
        {
            weak_match = udp;
        }
    }

    if (weak_match)
    {
        dbug_info(DBG_MOD_UDP, "udp_find: peer ip mismatch, fallback by local port");
        if (weak_match_used)
        {
            *weak_match_used = true;
        }
    }
    return weak_match;
}

net_err_t udp_input(pktbuf_t* buf, const ipaddr_t* src_ip, const ipaddr_t* dest_ip)
{
    net_err_t err = pktbuf_set_cont(buf, sizeof(ipv4_header_t));
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "udp_input: pktbuf_set_cont ipv4 hdr failed, err=%d", err);
        return err;
    }

    uint8_t* data = pktbuf_data(buf);
    int ip_hdr_size = ipv4_hdr_size((ipv4_pkt_t*)data);

    err = pktbuf_set_cont(buf, ip_hdr_size + (int)sizeof(udp_header_t));
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_UDP, "udp_input: pktbuf_set_cont failed, err=%d", err);
        return err;
    }

    data = pktbuf_data(buf);
    udp_pkt_t* udp_pkt = (udp_pkt_t*)(data + ip_hdr_size);
    uint16_t remote_port = x_ntohs(udp_pkt->header.src_port);
    uint16_t local_port = x_ntohs(udp_pkt->header.dest_port);

    bool weak_match = false;
    udp_t* udp = udp_find(src_ip, remote_port, dest_ip, local_port, &weak_match);
    if (udp == NULL)
    {
        dbug_warn(DBG_MOD_UDP,
                  "udp_input: no matching socket, src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u",
                  src_ip->a_addr[0], src_ip->a_addr[1], src_ip->a_addr[2], src_ip->a_addr[3], remote_port,
                  dest_ip->a_addr[0], dest_ip->a_addr[1], dest_ip->a_addr[2], dest_ip->a_addr[3], local_port);
        return NET_ERR_PORT_UNREACH;
    }

    pktbuf_remove_header(buf, ip_hdr_size);

    udp_pkt = (udp_pkt_t*)pktbuf_data(buf);
    uint16_t udp_len = x_ntohs(udp_pkt->header.length);
    if (udp_len < sizeof(udp_header_t) || udp_len > (uint16_t)buf->total_size)
    {
        dbug_warn(DBG_MOD_UDP, "udp_input: invalid packet");
        return NET_ERR_FRAME;
    }
    if (buf->total_size > udp_len)
    {
        err = pktbuf_resize(buf, udp_len);
        if (err != NET_ERR_OK)
        {
            dbug_warn(DBG_MOD_UDP, "udp_input: resize pkt failed");
            return err;
        }
        udp_pkt = (udp_pkt_t*)pktbuf_data(buf);
    }

    if (udp_pkt->header.checksum != 0)
    {
        pktbuf_reset_access(buf);
        uint16_t checksum = checksum16_pseudo(buf, src_ip, dest_ip, IPPROTO_UDP);
        if (checksum != 0)
        {
            bool accepted_with_connected_peer_ip = false;
            if (weak_match && !ipaddr_is_any(&udp->base.remote_ip))
            {
                // 网关/NAT改写源IP但未同步更新校验和时，按已连接的对端IP再校验一次
                pktbuf_reset_access(buf);
                checksum = checksum16_pseudo(buf, &udp->base.remote_ip, dest_ip, IPPROTO_UDP);
                accepted_with_connected_peer_ip = (checksum == 0);
            }

            if (!accepted_with_connected_peer_ip)
            {
                if (!(weak_match && !ipaddr_is_any(&udp->base.remote_ip)))
                {
                    dbug_warn(DBG_MOD_UDP, "udp_input: invalid checksum");
                    return NET_ERR_CHECKSUM;
                }

                dbug_info(DBG_MOD_UDP, "udp_input: checksum mismatch under weak peer match, accepted");
            }

            dbug_info(DBG_MOD_UDP, "udp_input: checksum mismatch on rewritten src ip, accepted by connected peer");
        }
    }

    udp_pkt->header.dest_port = x_ntohs(udp_pkt->header.dest_port);
    udp_pkt->header.src_port = x_ntohs(udp_pkt->header.src_port);
    udp_pkt->header.length = udp_len;
    if ((err = udp_pkt_invalid(udp_pkt, (int)buf->total_size)) != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_UDP, "udp_input: invalid packet");
        return err;
    }

    err = pktbuf_remove_header(buf, sizeof(udp_header_t));
    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_UDP, "udp_input: remove udp header failed");
        return err;
    }

    err = pktbuf_add_header(buf, sizeof(udp_from_t), true);
    if (err != NET_ERR_OK)
    {
        dbug_warn(DBG_MOD_UDP, "udp_input: add udp meta header failed");
        return err;
    }

    udp_from_t* from = (udp_from_t*)pktbuf_data(buf);
    if (weak_match && !ipaddr_is_any(&udp->base.remote_ip))
    {
        ipaddr_copy(&from->src_ip, &udp->base.remote_ip);
    }
    else
    {
        ipaddr_copy(&from->src_ip, src_ip);
    }
    from->src_port = remote_port;

    if (nlist_count(&udp->recv_list) >= UDP_RECV_QUEUE_LEN)
    {
        dbug_warn(DBG_MOD_UDP, "udp_input: recv queue full for port %d", local_port);
        return NET_ERR_MEM;
    }

    nlist_insert_last(&udp->recv_list, &buf->node);
    sock_wakeup(&udp->base,SOCK_WAIT_READ, NET_ERR_OK);
    return NET_ERR_OK;
}
