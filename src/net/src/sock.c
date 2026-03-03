#include "sock.h"
#include "dbug.h"
#include "raw.h"
#include "udp.h"
#include "sys_plat.h"
#include "socket.h"
#include "tool.h"
#include "tcp.h"

static x_socket_t socket_tbl[SOCKET_MAX_FD];

static int socket_get_fd(const x_socket_t* sock)
{
    return (int)(sock - socket_tbl);
}

static x_socket_t* socket_get(const int fd)
{
    if (fd < 0 || fd >= SOCKET_MAX_FD)
    {
        return NULL;
    }
    x_socket_t* sock = &socket_tbl[fd];
    if (sock->state != SOCK_STATE_USED)
    {
        return NULL;
    }
    return sock;
}

static x_socket_t* socket_alloc()
{
    for (int i = 0; i < SOCKET_MAX_FD; ++i)
    {
        if (socket_tbl[i].state == SOCK_STATE_FREE)
        {
            socket_tbl[i].state = SOCK_STATE_USED;
            return &socket_tbl[i];
        }
    }
    return NULL;
}

static void socket_free(x_socket_t* sock)
{
    if (sock)
    {
        sock->state = SOCK_STATE_FREE;
    }
}

net_err_t socket_init(void)
{
    plat_memset(socket_tbl, 0, sizeof(socket_tbl));
    return NET_ERR_OK;
}

net_err_t socket_create_req_in(const func_msg_t* msg)
{
    static const struct sock_info_t
    {
        sock_t* (*create)(int family, int protocol);
        int protocol;
    } sock_tbl[] = {
        [SOCK_RAW] = {.create = raw_create, .protocol = IPPROTO_ICMP},
        [SOCK_DGRAM] = {.create = udp_create, .protocol = IPPROTO_UDP},
        [SOCK_STREAM] = {.create = tcp_create, .protocol = IPPROTO_TCP},
    };

    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_alloc();
    if (s == NULL)
    {
        return NET_ERR_MEM;
    }

    if (req->create.type < 0 || req->create.type >= (int)(sizeof(sock_tbl) / sizeof(sock_tbl[0])))
    {
        socket_free(s);
        return NET_ERR_PROTOCOL;
    }

    struct sock_info_t info = sock_tbl[req->create.type];
    if (info.create == NULL)
    {
        socket_free(s);
        return NET_ERR_PROTOCOL;
    }
    if (req->create.protocol == 0)
    {
        req->create.protocol = info.protocol;
    }
    s->sock = info.create(req->create.family, req->create.protocol);
    if (s->sock == NULL)
    {
        socket_free(s);
        return NET_ERR_MEM;
    }

    req->fd = socket_get_fd(s);
    return NET_ERR_OK;
}

net_err_t socket_sendto_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_data_t* data = &req->data;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (s->sock->ops->sendto == NULL)
    {
        return NET_ERR_INVALID_STATE;
    }
    net_err_t err = s->sock->ops->sendto(s->sock, data->buf, data->len, data->flags, data->addr, *data->addrlen,
                                         &data->transferred_len);
    if (err == NET_ERR_NEED_WAIT && s->sock->send_wait)
    {
        sock_wait_add(s->sock->send_wait, s->sock->send_timeout, req);
    }
    if (err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_SOCK, "socket sendto failed, err=%d", err);
        return err;
    }
    return NET_ERR_OK;
}

net_err_t socket_recvfrom_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_data_t* data = &req->data;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (s->sock->ops->recvfrom == NULL)
    {
        return NET_ERR_INVALID_STATE;
    }
    net_err_t err = s->sock->ops->recvfrom(s->sock, data->buf, data->len, data->flags, data->addr, data->addrlen,
                                           &data->transferred_len);
    if (err == NET_ERR_NEED_WAIT && s->sock->recv_wait)
    {
        sock_wait_add(s->sock->recv_wait, s->sock->recv_timeout, req);
    }

    if (err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_SOCK, "socket recvfrom failed, err=%d", err);
        return err;
    }
    return NET_ERR_OK;
}

net_err_t socket_setsockopt_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    return s->sock->ops->setopt(s->sock, req->opt.level, req->opt.opt_name, req->opt.opt_val, req->opt.opt_len);
}

net_err_t socket_close_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (s->sock->ops->close == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = s->sock->ops->close(s->sock);

    if (err == NET_ERR_NEED_WAIT && s->sock->conn_wait)
    {
        sock_wait_add(s->sock->conn_wait, NET_CLOSE_WAIT_TIMEOUT * 1000, req);
    }
    else
    {
        socket_free(s);
    }
    return err;
}

net_err_t socket_connect_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }

    sock_conn_t* conn = &req->conn;
    if (s->sock->ops->connect == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = s->sock->ops->connect(s->sock, conn->addr, conn->addrlen);

    if (err == NET_ERR_NEED_WAIT && s->sock->conn_wait)
    {
        sock_wait_add(s->sock->conn_wait, s->sock->recv_timeout, req);
    }
    return err;
}

net_err_t socket_bind_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }

    sock_bind_t* bind = &req->bind;
    if (s->sock->ops->bind == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    return s->sock->ops->bind(s->sock, bind->addr, bind->addrlen);
}

net_err_t socket_send_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (req->conn.addr == NULL)
    {
        return NET_ERR_ADDR_UNSET;
    }
    if (s->sock->ops->send == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    return s->sock->ops->send(s->sock, req->data.buf, req->data.len, req->data.flags, &req->data.transferred_len);
}

net_err_t socket_recv_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (req->conn.addr == NULL)
    {
        return NET_ERR_ADDR_UNSET;
    }
    if (s->sock->ops->recv == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = s->sock->ops->recv(s->sock, req->data.buf, req->data.len, req->data.flags,
                                       &req->data.transferred_len);
    if (err == NET_ERR_NEED_WAIT && s->sock->recv_wait)
    {
        sock_wait_add(s->sock->recv_wait, s->sock->recv_timeout, req);
    }
    return err;
}

net_err_t socket_listen_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    sock_listen_t* listen = &req->listen;
    if (listen->backlog <= 0)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (s->sock->ops->listen == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    return s->sock->ops->listen(s->sock, listen->backlog);
}

net_err_t socket_accept_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }

    sock_accept_t* accept = &req->accept;
    sock_t* client = NULL;
    if (s->sock->ops->accept == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = s->sock->ops->accept(s->sock, accept->addr, accept->addrlen, &client);
    if (err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_SOCK, "socket accept failed, err=%d", err);
    }
    else if (err == NET_ERR_NEED_WAIT && s->sock->conn_wait)
    {
        sock_wait_add(s->sock->conn_wait, s->sock->recv_timeout, req);
    }
    else if (err == NET_ERR_OK && client)
    {
        x_socket_t* sock = socket_alloc();
        if (sock == NULL)
        {
            if (s->sock->ops->close)
            {
                s->sock->ops->close(client);
            }
            return NET_ERR_MEM;
        }
        sock->sock = client;
        accept->client_fd = socket_get_fd(sock);
    }
    return err;
}

net_err_t socket_destroy_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    x_socket_t* s = socket_get(req->fd);
    if (s == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (s->sock->ops->destroy)
    {
        s->sock->ops->destroy(s->sock);
    }
    socket_free(s);
    return NET_ERR_OK;
}

net_err_t sock_init(sock_t* sock, const int family, const int protocol, const sock_ops_t* ops)
{
    sock->family = family;
    sock->protocol = protocol;
    sock->ops = ops;
    sock->err = NET_ERR_OK;
    ipaddr_set_any(&sock->local_ip);
    ipaddr_set_any(&sock->remote_ip);
    nlist_node_init(&sock->node);
    sock->local_port = 0;
    sock->remote_port = 0;
    sock->recv_timeout = 0;
    sock->send_timeout = 0;
    sock->nonblock = 0;
    sock->send_wait = NULL;
    sock->recv_wait = NULL;
    sock->conn_wait = NULL;
    return NET_ERR_OK;
}

net_err_t sock_wait_init(sock_wait_t* wait)
{
    wait->waiting = 0;
    wait->err = NET_ERR_OK;
    wait->sem = sys_sem_create(0);
    if (wait->sem == SYS_SEM_INVALID)
    {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}

void sock_wait_destroy(sock_wait_t* wait)
{
    if (wait->sem != SYS_SEM_INVALID)
    {
        sys_sem_free(wait->sem);
        wait->sem = SYS_SEM_INVALID;
    }
}

void sock_wait_add(sock_wait_t* wait, const int timeout, sock_req_t* req)
{
    wait->waiting++;

    req->wait = wait;
    req->wait_timeout = timeout;
}

net_err_t sock_wait_enter(const sock_wait_t* wait, const int timeout)
{
    if (sys_sem_wait(wait->sem, timeout) < 0)
    {
        return NET_ERR_TIMEOUT;
    }
    return wait->err;
}

void sock_wait_leave(sock_wait_t* wait, const net_err_t err)
{
    if (wait->waiting > 0)
    {
        wait->waiting--;
        wait->err = err;
        sys_sem_notify(wait->sem);
    }
}

void sock_wakeup(const sock_t* sock, const int type, const net_err_t err)
{
    if (type & SOCK_WAIT_READ && sock->recv_wait)
    {
        sock_wait_leave(sock->recv_wait, err);
    }
    if (type & SOCK_WAIT_WRITE && sock->send_wait)
    {
        sock_wait_leave(sock->send_wait, err);
    }
    if (type & SOCK_WAIT_CONN && sock->conn_wait)
    {
        sock_wait_leave(sock->conn_wait, err);
    }
}

void sock_free(const sock_t* sock)
{
    if (sock == NULL)
    {
        return;
    }
    if (sock->recv_wait)
    {
        sock_wait_destroy(sock->recv_wait);
    }
    if (sock->send_wait)
    {
        sock_wait_destroy(sock->send_wait);
    }
    if (sock->conn_wait)
    {
        sock_wait_destroy(sock->conn_wait);
    }
}

net_err_t sock_setopt(sock_t* sock, int level, int opt_name, const void* opt_val, int opt_len)
{
    if (level != SOL_SOCKET)
    {
        return NET_ERR_OPTION;
    }

    switch (opt_name)
    {
    case SO_RCVTIMEO:
        if (opt_len != sizeof(x_timeval))
        {
            return NET_ERR_INVALID_PARAM;
        }
        x_timeval tv = *(const x_timeval*)opt_val;
        sock->recv_timeout = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
        break;
    case SO_SNDTIMEO:
        if (opt_len != sizeof(x_timeval))
        {
            return NET_ERR_INVALID_PARAM;
        }
        x_timeval stv = *(const x_timeval*)opt_val;
        sock->send_timeout = (stv.tv_sec * 1000) + (stv.tv_usec / 1000);
        break;
    case SO_SNDBUF:
        if (opt_len != sizeof(int))
        {
            return NET_ERR_INVALID_PARAM;
        }
        int sndbuf = *(const int*)opt_val;
        if (sndbuf < 0 || sndbuf > 1024 * 1024 * 1024) // 限制最大缓冲区大小为1GB
        {
            return NET_ERR_INVALID_PARAM;
        }
        sock->send_buf_size = sndbuf;
        break;
    case SO_RCVBUF:
        if (opt_len != sizeof(int))
        {
            return NET_ERR_INVALID_PARAM;
        }
        int rcvbuf = *(const int*)opt_val;
        if (rcvbuf < 0 || rcvbuf > 1024 * 1024 * 1024) // 限制最大缓冲区大小为1GB
        {
            return NET_ERR_INVALID_PARAM;
        }
        sock->recv_buf_size = rcvbuf;
        break;
    case SO_NONBLOCK:
        if (opt_len != sizeof(int))
        {
            return NET_ERR_INVALID_PARAM;
        }
        sock->nonblock = *(const int*)opt_val != 0;
        break;
    default:
        return NET_ERR_OPTION;
    }
    return NET_ERR_OK;
}

net_err_t sock_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen)
{
    struct x_sockaddr_in* remote = (struct x_sockaddr_in*)addr;
    ipaddr_from_buf(&sock->remote_ip, remote->sin_addr.addr_array);
    sock->remote_port = x_ntohs(remote->sin_port);
    return NET_ERR_OK;
}

net_err_t sock_send(sock_t* sock, const uint8_t* buf, const size_t len, const int flags, ssize_t* sent_size)
{
    struct x_sockaddr_in dest;
    dest.sin_family = sock->family;
    ipaddr_to_buf(&sock->remote_ip, dest.sin_addr.addr_array);
    dest.sin_port = x_htons(sock->remote_port);
    return sock->ops->sendto(sock, buf, len, flags, (struct x_sockaddr*)&dest, sizeof(struct x_sockaddr_in), sent_size);
}

net_err_t sock_recv(sock_t* sock, uint8_t* buf, const size_t len, const int flags, ssize_t* recv_size)
{
    struct x_sockaddr_in src;
    x_socklen_t src_len = sizeof(struct x_sockaddr_in);
    ipaddr_to_buf(&sock->remote_ip, src.sin_addr.addr_array);
    src.sin_port = x_htons(sock->remote_port);
    return sock->ops->recvfrom(sock, buf, len, flags, (struct x_sockaddr*)&src, &src_len, recv_size);
}

net_err_t sock_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t addrlen)
{
    struct x_sockaddr_in* local = (struct x_sockaddr_in*)addr;
    ipaddr_t local_ip;
    ipaddr_from_buf(&local_ip, local->sin_addr.addr_array);
    if (!ipaddr_is_any(&local_ip))
    {
        // IP地址不为0，验证地址是否合法
        route_entry_t* rt = find_route_entry(&local_ip);
        if (rt == NULL || !ipaddr_is_equal(&rt->netif->ipaddr, &local_ip))
        {
            dbug_error(DBG_MOD_SOCK, "sock_bind: local address is not valid");
            return NET_ERR_INVALID_PARAM;
        }
    }
    ipaddr_copy(&sock->local_ip, &local_ip);
    sock->local_port = x_ntohs(local->sin_port);
    return NET_ERR_OK;
}
