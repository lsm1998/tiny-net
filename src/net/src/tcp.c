#include "tcp.h"
#include "dbug.h"
#include "mblock.h"
#include "socket.h"
#include "tool.h"
#include "random.h"
#include "tcp_out.h"
#include "tcp_state.h"

static tcp_t tcp_tbl[TCP_MAX_NR];

static mblock_t tcp_mblock;

static nlist_t tcp_list;

bool tcp_has_pending_conn(const tcp_t* tcp)
{
    nlist_node_t* node;
    nlist_for_each(node, &tcp_list)
    {
        tcp_t* temp = nlist_entry(node, tcp_t, base.node);
        if (temp->state == TCP_STATE_ESTABLISHED && temp->parent == tcp && temp->flags.inactive)
        {
            return true;
        }
    }
    return false;
}

net_err_t tcp_init(void)
{
    plat_memset(tcp_tbl, 0, sizeof(tcp_tbl));

    nlist_init(&tcp_list);

    mblock_init(&tcp_mblock, tcp_tbl, sizeof(tcp_t), TCP_MAX_NR, NLOCKER_TYPE_NONE);

    dbug_info(DBG_MOD_TCP, "tcp init");
    return NET_ERR_OK;
}

static bool ipaddr_is_local(const ipaddr_t* ip)
{
    route_entry_t* route = find_route_entry(ip);
    return route != NULL && route->netif != NULL && ipaddr_is_equal(&route->netif->ipaddr, ip);
}

static net_err_t tcp_setopt(sock_t* sock, const int level, const int opt_name, const void* opt_val, const int opt_len)
{
    if (level == SOL_SOCKET)
    {
        if (opt_name == SO_KEEPALIVE)
        {
            tcp_t* tcp = (tcp_t*)sock;
            tcp_keep_alive_start(tcp, *(const int*)opt_val != 0);
            return NET_ERR_OK;
        }
        return sock_setopt(sock, level, opt_name, opt_val, opt_len);
    }
    if (opt_len != sizeof(int))
    {
        return NET_ERR_INVALID_PARAM;
    }
    tcp_t* tcp = (tcp_t*)sock;
    switch (opt_name)
    {
    case TCP_KEEPIDLE:
        tcp->conn.keep_idle = *(const int*)opt_val;
        tcp_keep_alive_reset(tcp);
        break;
    case TCP_KEEPINTVL:
        tcp->conn.keep_interval = *(const int*)opt_val;
        tcp_keep_alive_reset(tcp);
        break;
    case TCP_KEEPCNT:
        tcp->conn.keep_count = *(const int*)opt_val;
        tcp_keep_alive_reset(tcp);
        break;
    default:
        return NET_ERR_INVALID_PARAM;
    }
    return NET_ERR_OK;
}

static net_err_t tcp_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen)
{
    tcp_t* tcp = (tcp_t*)sock;
    if (tcp->state != TCP_STATE_CLOSE)
    {
        dbug_error(DBG_MOD_TCP, "tcp_bind: invalid state %s", tcp_state_name(tcp->state));
        return NET_ERR_STATE;
    }
    if (sock->local_port != NET_PORT_EMPTY)
    {
        dbug_error(DBG_MOD_TCP, "tcp_bind: already has local port %d", sock->local_port);
        return NET_ERR_INVALID_PARAM;
    }

    const struct x_sockaddr_in* addr_in = (const struct x_sockaddr_in*)addr;
    if (addr_in->sin_port == NET_PORT_EMPTY)
    {
        dbug_error(DBG_MOD_TCP, "tcp_bind: invalid local port");
        return NET_ERR_INVALID_PARAM;
    }

    // 如果绑定了特定IP，检查IP是否合法
    ipaddr_t bind_ip;
    ipaddr_from_buf(&bind_ip, addr_in->sin_addr.addr_array);
    if (!ipaddr_is_any(&bind_ip) && !ipaddr_is_local(&bind_ip))
    {
        dbug_error(DBG_MOD_TCP, "tcp_bind: invalid local ip");
        return NET_ERR_ADDR;
    }

    // 地址和端口是否已被占用
    nlist_node_t* node;
    nlist_for_each(node, &tcp_list)
    {
        tcp_t* temp = nlist_entry(node, tcp_t, base.node);
        if (&temp->base == sock)
        {
            continue;
        }
        if (temp->base.remote_port != NET_PORT_EMPTY)
        {
            // 已经连接的 TCP 连接不受 bind 的限制
            continue;
        }
        if (temp->base.local_port == addr_in->sin_port)
        {
            if (ipaddr_is_any(&bind_ip)
                || ipaddr_is_any(&temp->base.local_ip)
                || ipaddr_is_equal(&temp->base.local_ip, &bind_ip))
            {
                dbug_error(DBG_MOD_TCP, "tcp_bind: local port %d already in use", addr_in->sin_port);
                return NET_ERR_ADDR_IN_USE;
            }
        }
    }

    // 绑定地址
    sock->local_port = x_ntohs(addr_in->sin_port);
    ipaddr_from_buf(&sock->local_ip, addr_in->sin_addr.addr_array);
    return NET_ERR_OK;
}

static net_err_t tcp_listen(sock_t* sock, const int backlog)
{
    tcp_t* tcp = (tcp_t*)sock;
    if (tcp->state != TCP_STATE_CLOSE)
    {
        dbug_error(DBG_MOD_TCP, "tcp_listen: invalid state %s", tcp_state_name(tcp->state));
        return NET_ERR_STATE;
    }
    tcp->conn.backlog = backlog > TCP_BACKLOG_MAX ? TCP_BACKLOG_MAX : backlog;
    tcp_set_state(tcp, TCP_STATE_LISTEN);
    return NET_ERR_OK;
}

static net_err_t tcp_accept(sock_t* sock, struct x_sockaddr* addr, x_socklen_t* addrlen, sock_t** new_sock)
{
    tcp_t* tcp = (tcp_t*)sock;
    if (tcp->state != TCP_STATE_LISTEN)
    {
        dbug_error(DBG_MOD_TCP, "tcp_accept: invalid state %s", tcp_state_name(tcp->state));
        return NET_ERR_STATE;
    }

    nlist_node_t* node;
    nlist_for_each(node, &tcp_list)
    {
        tcp_t* temp = nlist_entry(node, tcp_t, base.node);
        // 找到一个符合条件的连接，返回给应用层
        if (temp->state == TCP_STATE_ESTABLISHED && temp->parent == tcp && temp->flags.inactive)
        {
            plat_memset(addr, 0, sizeof(struct x_sockaddr));
            struct x_sockaddr_in* addr_in = (struct x_sockaddr_in*)addr;
            addr_in->sin_family = AF_INET;
            ipaddr_to_buf(&temp->base.remote_ip, addr_in->sin_addr.addr_array);
            addr_in->sin_port = x_htons(temp->base.remote_port);
            *addrlen = sizeof(struct x_sockaddr_in);
            if (new_sock)
            {
                *new_sock = &temp->base;
            }
            temp->flags.inactive = 0; // 标记为活跃连接
            return NET_ERR_OK;
        }
    }

    return NET_ERR_NEED_WAIT;
}

static void tcp_destroy(sock_t* sock)
{
    tcp_t* tcp = (tcp_t*)sock;
    if (tcp->state == TCP_STATE_TIME_WAIT)
    {
        return;
    }
    tcp_free(tcp);
}

static uint16_t tcp_alloc_port()
{
    for (uint16_t port = NET_PORT_DYN_START; port <= NET_PORT_DYN_END; ++port)
    {
        bool port_in_use = false;

        nlist_node_t* node;
        nlist_for_each(node, &tcp_list)
        {
            tcp_t* tcp = nlist_entry(node, tcp_t, base.node);
            if (tcp->base.local_port == port)
            {
                port_in_use = true;
                break;
            }
        }

        if (!port_in_use)
        {
            return port;
        }
    }
    return NET_PORT_EMPTY; // 没有可用端口
}

static uint32_t tcp_get_isn()
{
    seed_xoshiro(time(NULL));
    return xoshiro256ss();
}

static void tcp_init_connect(tcp_t* tcp)
{
    tcp->send.isn = tcp_get_isn();
    tcp->send.un_ack_seq = tcp->send.next_seq = tcp->send.isn;
    tcp->recv.next_seq = 0;
}

static net_err_t tcp_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen)
{
    tcp_t* tcp = (tcp_t*)sock;

    if (tcp->state != TCP_STATE_CLOSE)
    {
        dbug_error(DBG_MOD_TCP, "tcp_connect: invalid state %s", tcp_state_name(tcp->state));
        return NET_ERR_STATE;
    }

    const struct x_sockaddr_in* dest_addr = (const struct x_sockaddr_in*)addr;

    ipaddr_from_buf(&sock->remote_ip, dest_addr->sin_addr.addr_array);
    sock->remote_port = x_ntohs(dest_addr->sin_port);

    if (sock->local_port == NET_PORT_EMPTY)
    {
        sock->local_port = tcp_alloc_port();
        if (sock->local_port == NET_PORT_EMPTY)
        {
            dbug_error(DBG_MOD_TCP, "tcp_connect: no free port");
            return NET_ERR_FULL;
        }
    }

    if (ipaddr_is_any(&sock->local_ip))
    {
        // 查路由表
        route_entry_t* route = find_route_entry(&sock->remote_ip);
        if (route == NULL)
        {
            dbug_error(DBG_MOD_TCP, "tcp_connect: no route to remote ip");
            return NET_ERR_IP_UNREACH;
        }
        ipaddr_copy(&sock->local_ip, &route->netif->ipaddr);
    }

    net_err_t err;
    tcp_init_connect(tcp);

    if ((err = tcp_send_syn(tcp)) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "tcp_connect: tcp_send_syn failed");
        return err;
    }
    tcp_set_state(tcp, TCP_STATE_SYN_SENT);

    return NET_ERR_NEED_WAIT;
}

void tcp_free(tcp_t* tcp)
{
    sock_wait_destroy(&tcp->conn.wait);
    sock_wait_destroy(&tcp->send.wait);
    sock_wait_destroy(&tcp->recv.wait);
    if (tcp->send.data)
    {
        free(tcp->send.data);
        tcp->send.data = NULL;
    }
    if (tcp->recv.data)
    {
        free(tcp->recv.data);
        tcp->recv.data = NULL;
    }
    tcp->state = TCP_STATE_FREE;
    nlist_remove(&tcp_list, &tcp->base.node);
    mblock_free(&tcp_mblock, tcp);
}

static void tcp_clear_with_parent(const tcp_t* tcp)
{
    nlist_node_t* node = tcp_list.first;
    while (node)
    {
        nlist_node_t* next = node->next;
        tcp_t* temp = nlist_entry(node, tcp_t, base.node);
        // 仅清理监听队列中尚未被 accept 的 child，已 accept 的连接继续存活
        if (temp->parent == tcp && temp->flags.inactive)
        {
            temp->parent = NULL;
            tcp_abort(temp, NET_ERR_CLOSE);
            tcp_free(temp);
        }
        node = next;
    }
}

static net_err_t tcp_close(sock_t* sock)
{
    tcp_t* tcp = (tcp_t*)sock;
    switch (tcp->state)
    {
    case TCP_STATE_CLOSE:
        tcp_free(tcp);
        return NET_ERR_OK;
    case TCP_STATE_SYN_SENT:
    case TCP_STATE_SYN_RECEIVED:
        tcp_abort(tcp, NET_ERR_CLOSE);
        tcp_free(tcp);
        break;
    case TCP_STATE_CLOSE_WAIT:
        tcp_send_fin(tcp);
        tcp_set_state(tcp, TCP_STATE_LAST_ACK);
        return NET_ERR_NEED_WAIT;
    case TCP_STATE_ESTABLISHED:
        tcp_send_fin(tcp);
        tcp_set_state(tcp, TCP_STATE_FIN_WAIT_1);
        return NET_ERR_NEED_WAIT;
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
        dbug_error(DBG_MOD_TCP, "tcp_close: close in state %s", tcp_state_name(tcp->state));
        break;
    case TCP_STATE_LISTEN:
        tcp_clear_with_parent(tcp);
        tcp_abort(tcp, NET_ERR_CLOSE);
        tcp_free(tcp);
    default:
        break;
    }
    return NET_ERR_OK;
}

static net_err_t tcp_send(sock_t* sock, const uint8_t* buf, const size_t len, const int flags, ssize_t* sent_size)
{
    tcp_t* tcp = (tcp_t*)sock;
    int send_n = 0;
    switch (tcp->state)
    {
    case TCP_STATE_CLOSE:
        return NET_ERR_CLOSE;
    case TCP_STATE_ESTABLISHED:
        send_n = tcp_write_send_buf(tcp, buf, len);
        if (send_n <= 0)
        {
            *sent_size = 0;
            return NET_ERR_NEED_WAIT;
        }
        *sent_size = (ssize_t)send_n;
        // tcp_transmit(tcp);
        tcp_out_event(tcp, TCP_OUT_EVENT_SEND);
        return NET_ERR_OK;
    default:
        dbug_error(DBG_MOD_TCP, "tcp_send: invalid state %s", tcp_state_name(tcp->state));
        return NET_ERR_STATE;
    }
}

static net_err_t tcp_recv(sock_t* sock, uint8_t* buf, const size_t len, const int flags, ssize_t* recv_size)
{
    tcp_t* tcp = (tcp_t*)sock;
    net_err_t need_wait = NET_ERR_NEED_WAIT;
    int cnt;
    switch (tcp->state)
    {
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_CLOSE:
        return NET_ERR_CLOSE;
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
        if (tcp_buf_available(&tcp->recv.buf) == 0)
        {
            return NET_ERR_CLOSE;
        }
        need_wait = NET_ERR_OK;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_ESTABLISHED:
        // 从接收缓冲区读取数据
        cnt = tcp_buf_read_recv(&tcp->recv.buf, buf, (int)len);
        if (cnt > 0)
        {
            *recv_size = (ssize_t)cnt;
            return NET_ERR_OK;
        }
        *recv_size = 0;
        return need_wait;
    default:
        dbug_error(DBG_MOD_TCP, "tcp_recv: invalid state %s", tcp_state_name(tcp->state));
        return NET_ERR_STATE;
    }
}

static uint32_t tcp_poll(sock_t* sock)
{
    tcp_t* tcp = (tcp_t*)sock;
    uint32_t events = 0;

    switch (tcp->state)
    {
    case TCP_STATE_LISTEN:
        if (tcp_has_pending_conn(tcp))
        {
            events |= X_POLLIN;
        }
        break;
    case TCP_STATE_CLOSE:
    case TCP_STATE_TIME_WAIT:
        events |= X_POLLHUP;
        break;
    case TCP_STATE_SYN_SENT:
    case TCP_STATE_SYN_RECEIVED:
        break;
    default:
        if (tcp_buf_count(&tcp->recv.buf) > 0 || tcp->flags.fin_in)
        {
            events |= X_POLLIN;
        }
        if ((tcp->state == TCP_STATE_ESTABLISHED || tcp->state == TCP_STATE_CLOSE_WAIT) &&
            tcp_buf_available(&tcp->send.buf) > 0)
        {
            events |= X_POLLOUT;
        }
        if (tcp->flags.fin_in || tcp->state == TCP_STATE_LAST_ACK || tcp->state == TCP_STATE_CLOSING)
        {
            events |= X_POLLHUP;
        }
        break;
    }

    if (sock->err < NET_ERR_OK && sock->err != NET_ERR_CLOSE)
    {
        events |= X_POLLERR;
    }
    return events;
}

static tcp_t* tcp_get_free(const bool wait)
{
    tcp_t* tcp = mblock_alloc(&tcp_mblock, wait ? 0 : -1);
    if (tcp == NULL)
    {
        // 从time wait状态的连接中回收
        nlist_node_t* node;
        nlist_for_each(node, &tcp_list)
        {
            tcp_t* temp = nlist_entry(node, tcp_t, base.node);
            if (temp->state == TCP_STATE_TIME_WAIT)
            {
                tcp_free(temp);
                tcp = mblock_alloc(&tcp_mblock, wait ? 0 : -1);
                if (tcp != NULL)
                {
                    return tcp;
                }
            }
        }
        dbug_error(DBG_MOD_TCP, "tcp_get_free: no free tcp");
        return NULL;
    }
    return tcp;
}

tcp_t* tcp_find(const ipaddr_t* local_ip, const uint16_t local_port, const ipaddr_t* remote_ip,
                const uint16_t remote_port)
{
    tcp_t* wild_match = NULL;
    nlist_node_t* node;
    nlist_for_each(node, &tcp_list)
    {
        tcp_t* tcp = nlist_entry(node, tcp_t, base.node);
        if (tcp->base.local_port != local_port)
        {
            continue;
        }

        // local_ip 匹配
        if (!ipaddr_is_any(&tcp->base.local_ip) && !ipaddr_is_equal(&tcp->base.local_ip, local_ip))
        {
            continue;
        }

        // remote_ip + remote_port 匹配
        bool remote_ip_match = ipaddr_is_any(&tcp->base.remote_ip) || ipaddr_is_equal(&tcp->base.remote_ip, remote_ip);
        bool remote_port_match = tcp->base.remote_port == 0 || tcp->base.remote_port == remote_port;
        if (!remote_ip_match || !remote_port_match)
        {
            continue;
        }

        // 精确匹配
        if (tcp->base.remote_port == remote_port &&
            ipaddr_is_equal(&tcp->base.remote_ip, remote_ip) &&
            ipaddr_is_equal(&tcp->base.local_ip, local_ip))
        {
            return tcp;
        }

        // 记录候选，继续查找更精确的
        if (wild_match == NULL)
        {
            wild_match = tcp;
        }
    }
    return wild_match;
}

static tcp_t* tcp_alloc(const bool wait, const int family, const int protocol)
{
    tcp_t* tcp = tcp_get_free(wait);
    if (tcp == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_create: no memory for tcp");
        return NULL;
    }

    plat_memset(tcp, 0, sizeof(tcp_t));
    tcp_set_state(tcp, TCP_STATE_CLOSE);
    tcp->conn.keep_idle = TCP_KEEP_IDLE;
    tcp->conn.keep_interval = TCP_KEEP_INTERVAL;
    tcp->conn.keep_count = TCP_KEEP_COUNT;
    tcp->send.ostate = TCP_OSTATE_IDLE;
    tcp->send.rto = TCP_INIT_RTO;
    tcp->send.retrans_max = TCP_INIT_RETRIES;

    static const sock_ops_t tcp_ops = {
        .send = tcp_send,
        .recv = tcp_recv,
        .setopt = tcp_setopt,
        .close = tcp_close,
        .connect = tcp_connect,
        .bind = tcp_bind,
        .listen = tcp_listen,
        .accept = tcp_accept,
        .destroy = tcp_destroy,
        .poll = tcp_poll,
    };

    net_err_t err = sock_init(&tcp->base, family, protocol, &tcp_ops);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "tcp_create: sock_init failed");
        goto create_fail;
    }

    if (sock_wait_init(&tcp->conn.wait) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "tcp_create: sock_wait_init failed");
        goto create_fail;
    }
    tcp->base.conn_wait = &tcp->conn.wait;

    if (sock_wait_init(&tcp->send.wait) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "tcp_create: sock_wait_init failed");
        goto create_fail;
    }
    tcp->base.send_wait = &tcp->send.wait;

    if (sock_wait_init(&tcp->recv.wait) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "tcp_create: sock_wait_init failed");
        goto create_fail;
    }
    tcp->base.recv_wait = &tcp->recv.wait;

    // 是否是间接交付
    route_entry_t* route = find_route_entry(&tcp->base.remote_ip);
    if (route == NULL || route->netif->mtu == 0 || !ipaddr_is_any(&route->next_hop))
    {
        tcp->mss = TCP_DEFAULT_MSS; // RFC1122, 加上IP和TCP头，总共576字节
    }
    else
    {
        tcp->mss = route->netif->mtu - (int)sizeof(ipv4_header_t) - (int)sizeof(tcp_header_t);
    }

    // 初始化发送/接收缓冲区
    if (tcp->base.send_buf_size == 0)
    {
        tcp->base.send_buf_size = TCP_SEND_BUF_SIZE;
    }
    if (tcp->base.recv_buf_size == 0)
    {
        tcp->base.recv_buf_size = TCP_RECV_BUF_SIZE;
    }

    tcp->send.data = (uint8_t*)malloc(tcp->base.send_buf_size);
    tcp->recv.data = (uint8_t*)malloc(tcp->base.recv_buf_size);
    tcp_buf_init(&tcp->send.buf, tcp->send.data, tcp->base.send_buf_size);
    tcp_buf_init(&tcp->recv.buf, tcp->recv.data, tcp->base.recv_buf_size);

    return tcp;

create_fail:
    sock_free(&tcp->base);
    if (tcp->base.conn_wait)
    {
        sock_wait_destroy(tcp->base.conn_wait);
    }
    if (tcp->base.send_wait)
    {
        sock_wait_destroy(tcp->base.send_wait);
    }
    if (tcp->base.recv_wait)
    {
        sock_wait_destroy(tcp->base.recv_wait);
    }
    mblock_free(&tcp_mblock, tcp);
    return NULL;
}

static void tcp_insert(tcp_t* tcp)
{
    nlist_insert_last(&tcp_list, &tcp->base.node);
}

sock_t* tcp_create(const int family, const int protocol)
{
    tcp_t* tcp = tcp_alloc(true, family, protocol);
    if (tcp == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_create: tcp_alloc failed");
        return NULL;
    }
    tcp_insert(tcp);
    return &tcp->base;
}

size_t tcp_header_size(const tcp_header_t* header)
{
    return header->f_data_offset * 4;
}

void tcp_set_header_size(tcp_header_t* header, const size_t size)
{
    header->f_data_offset = size / 4;
}

net_err_t tcp_abort(tcp_t* tcp, const net_err_t err)
{
    tcp_set_state(tcp, TCP_STATE_CLOSE);
    sock_wakeup(&tcp->base, SOCK_WAIT_ALL, err);
    tcp_kill_all_timer(tcp);
    return NET_ERR_OK;
}

void tcp_read_options(tcp_t* tcp, tcp_header_t* header)
{
    uint8_t* options = (uint8_t*)header + sizeof(tcp_header_t);
    uint8_t* options_end = (uint8_t*)header + tcp_header_size(header);

    if (options >= options_end)
    {
        return; // 没有选项
    }
    tcp_option_mss_t* mss_option = NULL;

    while (options < options_end)
    {
        uint8_t kind = *options;

        switch (kind)
        {
        case TCP_OPTION_END: // 选项结束
            return;
        case TCP_OPTION_NOP: // NOP，无操作
            break;
        case TCP_OPTION_MSS: // MSS，最大报文段长度
            mss_option = (tcp_option_mss_t*)options;
            uint16_t mss = x_ntohs(mss_option->mss);
            if (mss < tcp->mss || tcp->mss == 0)
            {
                tcp->mss = mss;
            }
            break;
        default:
            break;
        }
        options += kind == TCP_OPTION_NOP ? 1 : options[1]; // NOP选项长度为1，其他选项长度由第二个字节指定
    }
}

int tcp_recv_window_size(const tcp_t* tcp)
{
    return tcp_buf_available(&tcp->recv.buf);
}

static void tcp_keep_alive_timeout(net_timer_t* timer, void* arg)
{
    tcp_t* tcp = arg;

    if (++tcp->conn.keep_retry < tcp->conn.keep_count)
    {
        // 启动新的keep-alive定时器
        net_timer_add(&tcp->conn.keep_timer, "tcp_keep_alive", tcp_keep_alive_timeout, tcp,
                      tcp->conn.keep_interval * 1000, 0);

        // 发送keep-alive探测报文
        if (tcp_send_keep_alive(tcp) != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_TCP, "tcp_keep_alive_timeout: tcp_send_keep_alive failed");
            return;
        }
    }
    else
    {
        // 超过最大重试次数，认为连接已断开
        dbug_warn(DBG_MOD_TCP, "tcp_keep_alive_timeout: keep-alive retry count exceeded, closing connection");
        tcp_send_reset_with_tcp(tcp);
        tcp_abort(tcp, NET_ERR_CLOSE);
    }
}

static void tcp_keep_alive_start_timer(tcp_t* tcp)
{
    net_timer_add(&tcp->conn.keep_timer, "tcp_keep_alive", tcp_keep_alive_timeout, tcp,
                  tcp->conn.keep_idle * 1000, 0);
}

void tcp_keep_alive_start(tcp_t* tcp, const bool enable)
{
    if (tcp->flags.keep_alive && !enable)
    {
        net_timer_remove(&tcp->conn.keep_timer);
    }
    else if (!tcp->flags.keep_alive && enable)
    {
        tcp_keep_alive_start_timer(tcp);
    }
    tcp->flags.keep_alive = enable;
}

void tcp_keep_alive_reset(tcp_t* tcp)
{
    if (tcp->flags.keep_alive)
    {
        net_timer_remove(&tcp->conn.keep_timer);
        tcp_keep_alive_start_timer(tcp);
        tcp->conn.keep_retry = 0;
    }
}

void tcp_kill_all_timer(const tcp_t* tcp)
{
    net_timer_remove(&tcp->conn.keep_timer);
    net_timer_remove(&tcp->send.retrans_timer);
}

bool tcp_backlog_full(const tcp_t* tcp)
{
    int count = 0;
    nlist_node_t* node;
    nlist_for_each(node, &tcp_list)
    {
        tcp_t* temp = nlist_entry(node, tcp_t, base.node);
        if (temp->parent == tcp && temp->flags.inactive)
        {
            ++count;
        }
    }
    return count >= tcp->conn.backlog;
}

tcp_t* tcp_create_child(tcp_t* parent, const tcp_seg_t* seg)
{
    tcp_t* child = tcp_alloc(false, parent->base.family, parent->base.protocol);
    if (child == NULL)
    {
        return NULL;
    }

    tcp_init_connect(child);

    tcp_set_state(child, TCP_STATE_SYN_RECEIVED);
    child->parent = parent;

    // 继承父连接的本地IP和端口
    ipaddr_copy(&child->base.local_ip, &seg->local_ip);
    child->base.local_port = seg->header->dest_port;

    // 设置远程IP和端口
    ipaddr_copy(&child->base.remote_ip, &seg->remote_ip);
    child->base.remote_port = seg->header->src_port;

    child->flags.irs_valid = 1;
    child->flags.inactive = 1;

    child->recv.isn = seg->seq;
    child->recv.next_seq = seg->seq + 1;

    tcp_read_options(child, seg->header);

    tcp_insert(child);
    return child;
}
