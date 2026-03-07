#include "raw.h"
#include "dbug.h"
#include "mblock.h"
#include "ipv4.h"
#include "sock.h"
#include "socket.h"

static raw_t raw_tbl[RAW_MAX_NR];

static mblock_t raw_mblock;

static nlist_t raw_list;

net_err_t raw_init()
{
    plat_memset(raw_tbl, 0, sizeof(raw_tbl));

    nlist_init(&raw_list);

    mblock_init(&raw_mblock, raw_tbl, sizeof(raw_t), RAW_MAX_NR, NLOCKER_TYPE_NONE);
    dbug_info(DBG_MOD_RAW, "init raw");
    return NET_ERR_OK;
}

static net_err_t raw_sendto(sock_t* sock, const uint8_t* buf, const size_t len, int flags,
                            const struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t* sent_size)
{
    ipaddr_t dest_ip;

    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);

    if (!ipaddr_is_any(&sock->remote_ip) && !ipaddr_is_equal(&dest_ip, &sock->remote_ip))
    {
        dbug_error(DBG_MOD_RAW, "raw_sendto: destination address is any");
        return NET_ERR_INVALID_PARAM;
    }

    pktbuf_t* pktbuf = pktbuf_alloc((int)len);
    if (pktbuf == NULL)
    {
        dbug_error(DBG_MOD_RAW, "raw_sendto: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }

    net_err_t err = pktbuf_write(pktbuf, buf, (int)len);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_RAW, "raw_sendto: pktbuf_write failed, err=%d", err);
        pktbuf_free(pktbuf);
        return err;
    }

    if (ipaddr_is_any(&sock->local_ip))
    {
        sock->local_ip = netif_get_default()->ipaddr;
    }

    err = ipv4_output(sock->protocol, &dest_ip, &sock->local_ip, pktbuf);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_RAW, "raw_sendto: ipv4_output failed, err=%d", err);
        pktbuf_free(pktbuf);
        return err;
    }
    *sent_size = (ssize_t)len;
    return NET_ERR_OK;
}

static net_err_t raw_recvfrom(sock_t* sock, uint8_t* buf, const size_t len, int flags,
                              const struct x_sockaddr* src, x_socklen_t* src_len, ssize_t* recv_size)
{
    raw_t* raw = (raw_t*)sock;
    nlist_node_t* frist = nlist_remove_first(&raw->recv_list);
    if (frist == NULL)
    {
        *recv_size = 0;
        return NET_ERR_NEED_WAIT;
    }
    pktbuf_t* pktbuf = nlist_entry(frist, pktbuf_t, node);

    ipv4_header_t* ip_header = (ipv4_header_t*)pktbuf_data(pktbuf);
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)src;
    plat_memset(addr, 0, sizeof(struct x_sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    plat_memcpy(&addr->sin_addr, ip_header->src_addr, IPV4_ADDR_LEN);
    if (src_len != NULL)
    {
        *src_len = sizeof(struct x_sockaddr_in);
    }

    size_t copy_size = pktbuf->total_size < len ? pktbuf->total_size : len;
    pktbuf_reset_access(pktbuf);
    net_err_t err = pktbuf_read(pktbuf, buf, (int)copy_size);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_RAW, "raw_recvfrom: pktbuf_read failed, err=%d", err);
        pktbuf_free(pktbuf);
        return err;
    }
    pktbuf_free(pktbuf);
    *recv_size = (ssize_t)copy_size;
    return NET_ERR_OK;
}

static net_err_t raw_close(sock_t* sock)
{
    raw_t* raw = (raw_t*)sock;

    // 从全局列表中移除
    nlist_remove(&raw_list, &raw->base.node);

    // 移除消息队列中的数据包
    nlist_node_t* node;
    while ((node = nlist_remove_first(&raw->recv_list)) != NULL)
    {
        pktbuf_t* pktbuf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(pktbuf);
    }

    // 释放sock
    sock_free(sock);

    // 释放raw内存块
    mblock_free(&raw_mblock, raw);
    return NET_ERR_OK;
}

static uint32_t raw_poll(sock_t* sock)
{
    raw_t* raw = (raw_t*)sock;
    uint32_t events = X_POLLOUT;
    if (nlist_count(&raw->recv_list) > 0)
    {
        events |= X_POLLIN;
    }
    if (sock->err < NET_ERR_OK)
    {
        events |= X_POLLERR;
    }
    return events;
}

sock_t* raw_create(const int family, const int protocol)
{
    static const sock_ops_t raw_ops = {
        .sendto = raw_sendto,
        .recvfrom = raw_recvfrom,
        .setopt = sock_setopt,
        .close = raw_close,
        .connect = sock_connect,
        .send = sock_send,
        .recv = sock_recv,
        .bind = sock_bind,
        .poll = raw_poll,
    };
    raw_t* raw = mblock_alloc(&raw_mblock, -1);
    if (raw == NULL)
    {
        dbug_error(DBG_MOD_RAW, "raw_create: no memory for raw");
        return NULL;
    }

    net_err_t err = sock_init(&raw->base, family, protocol, &raw_ops);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_RAW, "raw_create: sock_init failed");
        goto create_fail;
    }

    raw->base.recv_wait = &raw->recv_wait;
    if ((err = sock_wait_init(&raw->recv_wait)) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_RAW, "raw_create: sock_wait_init failed,err:%d", err);
        goto create_fail;
    }

    nlist_insert_last(&raw_list, &raw->base.node);
    nlist_init(&raw->recv_list);

    return &raw->base;

create_fail:
    sock_free(&raw->base);
    mblock_free(&raw_mblock, raw);
    return NULL;
}

static raw_t* raw_find(const ipaddr_t* src_ip, const ipaddr_t* dest_ip, const uint8_t protocol)
{
    nlist_node_t* node;
    nlist_for_each(node, &raw_list)
    {
        raw_t* raw = (raw_t*)nlist_entry(node, sock_t, node);

        if (raw->base.protocol && (raw->base.protocol != protocol))
        {
            continue;
        }
        if (!ipaddr_is_any(&raw->base.remote_ip) && !ipaddr_is_equal(&raw->base.remote_ip, src_ip))
        {
            continue;
        }
        if (!ipaddr_is_any(&raw->base.local_ip) && !ipaddr_is_equal(&raw->base.local_ip, dest_ip))
        {
            continue;
        }
        return raw;
    }
    return NULL;
}

net_err_t raw_input(pktbuf_t* pktbuf)
{
    ipv4_header_t* ip_header = (ipv4_header_t*)pktbuf_data(pktbuf);

    ipaddr_t src_ip, dest_ip;
    ipaddr_from_buf(&src_ip, ip_header->src_addr);
    ipaddr_from_buf(&dest_ip, ip_header->dest_addr);

    raw_t* raw = raw_find(&src_ip, &dest_ip, ip_header->protocol);
    if (raw == NULL)
    {
        dbug_warn(DBG_MOD_RAW, "raw_input: no matching raw socket for protocol %d", ip_header->protocol);
        return NET_ERR_TARGET_ADDR_MATCH;
    }

    if (nlist_count(&raw->recv_list) >= RAW_RECV_QUEUE_LEN)
    {
        dbug_warn(DBG_MOD_RAW, "raw_input: recv queue full, dropping packet");
        pktbuf_free(pktbuf);
        return NET_ERR_MEM;
    }

    nlist_insert_last(&raw->recv_list, &pktbuf->node);
    sock_wakeup(&raw->base,SOCK_WAIT_READ, NET_ERR_OK);
    return NET_ERR_OK;
}
