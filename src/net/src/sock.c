#include "sock.h"
#include "dbug.h"
#include "epoll.h"
#include "raw.h"
#include "udp.h"
#include "sys_plat.h"
#include "socket.h"
#include "select.h"
#include "tool.h"
#include "tcp.h"

static x_socket_t fd_tbl[NET_FD_MAX];
static sys_mutex_t fd_tbl_lock = SYS_MUTEX_INVALID;

static void fd_lock(void)
{
    if (fd_tbl_lock != SYS_MUTEX_INVALID)
    {
        sys_mutex_lock(fd_tbl_lock);
    }
}

static void fd_unlock(void)
{
    if (fd_tbl_lock != SYS_MUTEX_INVALID)
    {
        sys_mutex_unlock(fd_tbl_lock);
    }
}

static int fd_get_index(const x_socket_t* entry)
{
    return (int)(entry - fd_tbl);
}

static x_socket_t* fd_get(const int fd)
{
    if (fd < 0 || fd >= NET_FD_MAX)
    {
        return NULL;
    }
    x_socket_t* entry = &fd_tbl[fd];
    if (entry->type == X_FD_TYPE_NONE)
    {
        return NULL;
    }
    return entry;
}

static x_socket_t* fd_alloc(const x_fd_type_t type, void* ptr)
{
    for (int i = 0; i < NET_FD_MAX; ++i)
    {
        if (fd_tbl[i].type == X_FD_TYPE_NONE)
        {
            fd_tbl[i].type = type;
            fd_tbl[i].ptr = ptr;
            return &fd_tbl[i];
        }
    }
    return NULL;
}

static void fd_release_entry(x_socket_t* entry)
{
    if (entry)
    {
        entry->type = X_FD_TYPE_NONE;
        entry->ptr = NULL;
    }
}

net_err_t socket_init(void)
{
    plat_memset(fd_tbl, 0, sizeof(fd_tbl));
    if (fd_tbl_lock == SYS_MUTEX_INVALID)
    {
        fd_tbl_lock = sys_mutex_create();
        if (fd_tbl_lock == SYS_MUTEX_INVALID)
        {
            return NET_ERR_SYS;
        }
    }
    net_err_t err = x_select_init();
    if (err != NET_ERR_OK)
    {
        sys_mutex_free(fd_tbl_lock);
        fd_tbl_lock = SYS_MUTEX_INVALID;
        return err;
    }
    return NET_ERR_OK;
}

x_fd_type_t sock_fd_type(const int fd)
{
    fd_lock();
    x_socket_t* entry = fd_get(fd);
    const x_fd_type_t type = entry ? entry->type : X_FD_TYPE_NONE;
    fd_unlock();
    return type;
}

int sock_fd_alloc_socket(sock_t* sock)
{
    fd_lock();
    x_socket_t* entry = fd_alloc(X_FD_TYPE_SOCKET, sock);
    const int fd = entry ? fd_get_index(entry) : -1;
    fd_unlock();
    return fd;
}

int sock_fd_alloc_epoll(struct x_epoll* epoll)
{
    fd_lock();
    x_socket_t* entry = fd_alloc(X_FD_TYPE_EPOLL, epoll);
    const int fd = entry ? fd_get_index(entry) : -1;
    fd_unlock();
    return fd;
}

sock_t* sock_fd_get_socket(const int fd)
{
    fd_lock();
    x_socket_t* entry = fd_get(fd);
    sock_t* sock = (entry && entry->type == X_FD_TYPE_SOCKET) ? entry->sock : NULL;
    fd_unlock();
    return sock;
}

struct x_epoll* sock_fd_get_epoll(const int fd)
{
    fd_lock();
    x_socket_t* entry = fd_get(fd);
    struct x_epoll* epoll = (entry && entry->type == X_FD_TYPE_EPOLL) ? entry->epoll : NULL;
    fd_unlock();
    return epoll;
}

void sock_fd_release(const int fd)
{
    fd_lock();
    x_socket_t* entry = fd_get(fd);
    if (entry)
    {
        fd_release_entry(entry);
    }
    fd_unlock();
    x_select_wakeup();
}

int sock_fd_poll_events(const int fd, uint32_t* events)
{
    if (events == NULL)
    {
        return -1;
    }

    x_fd_type_t type = sock_fd_type(fd);
    switch (type)
    {
    case X_FD_TYPE_SOCKET:
        {
            sock_t* sock = sock_fd_get_socket(fd);
            if (sock == NULL || sock->ops == NULL || sock->ops->poll == NULL)
            {
                return -1;
            }
            *events = sock->ops->poll(sock);
            return 0;
        }
    case X_FD_TYPE_EPOLL:
        *events = x_epoll_poll_events(fd);
        return 0;
    case X_FD_TYPE_NONE:
    default:
        return -1;
    }
}

static void sock_dispose(sock_t* sock)
{
    if (sock == NULL || sock->ops == NULL)
    {
        return;
    }
    if (sock->ops->destroy)
    {
        sock->ops->destroy(sock);
    }
    else if (sock->ops->close)
    {
        sock->ops->close(sock);
    }
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

    if (req->create.type < 0 || req->create.type >= (int)(sizeof(sock_tbl) / sizeof(sock_tbl[0])))
    {
        return NET_ERR_PROTOCOL;
    }

    struct sock_info_t info = sock_tbl[req->create.type];
    if (info.create == NULL)
    {
        return NET_ERR_PROTOCOL;
    }
    if (req->create.protocol == 0)
    {
        req->create.protocol = info.protocol;
    }
    sock_t* sock = info.create(req->create.family, req->create.protocol);
    if (sock == NULL)
    {
        return NET_ERR_MEM;
    }

    req->fd = sock_fd_alloc_socket(sock);
    if (req->fd < 0)
    {
        sock_dispose(sock);
        return NET_ERR_MEM;
    }
    return NET_ERR_OK;
}

net_err_t socket_sendto_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_data_t* data = &req->data;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->ops->sendto == NULL)
    {
        return NET_ERR_INVALID_STATE;
    }
    net_err_t err = sock->ops->sendto(sock, data->buf, data->len, data->flags, data->addr, *data->addrlen,
                                      &data->transferred_len);
    if (err == NET_ERR_NEED_WAIT && sock->send_wait)
    {
        sock_wait_add(sock->send_wait, sock->send_timeout, req);
    }
    if (err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_SOCK, "socket sendto failed, err=%d", err);
        return err;
    }
    return err;
}

net_err_t socket_recvfrom_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_data_t* data = &req->data;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->ops->recvfrom == NULL)
    {
        return NET_ERR_INVALID_STATE;
    }
    net_err_t err = sock->ops->recvfrom(sock, data->buf, data->len, data->flags, data->addr, data->addrlen,
                                        &data->transferred_len);
    if (err == NET_ERR_NEED_WAIT && sock->recv_wait)
    {
        sock_wait_add(sock->recv_wait, sock->recv_timeout, req);
    }

    if (err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_SOCK, "socket recvfrom failed, err=%d", err);
        return err;
    }
    return err;
}

net_err_t socket_setsockopt_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    return sock->ops->setopt(sock, req->opt.level, req->opt.opt_name, req->opt.opt_val, req->opt.opt_len);
}

net_err_t socket_close_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->ops->close == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    x_epoll_sock_close(sock, req->fd);
    net_err_t err = sock->ops->close(sock);

    if (err == NET_ERR_NEED_WAIT && sock->conn_wait)
    {
        sock_wait_add(sock->conn_wait, NET_CLOSE_WAIT_TIMEOUT * 1000, req);
    }
    else
    {
        sock_fd_release(req->fd);
    }
    return err;
}

net_err_t socket_connect_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }

    sock_conn_t* conn = &req->conn;
    if (sock->ops->connect == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = sock->ops->connect(sock, conn->addr, conn->addrlen);

    if (err == NET_ERR_NEED_WAIT && sock->conn_wait)
    {
        sock_wait_add(sock->conn_wait, sock->recv_timeout, req);
    }
    return err;
}

net_err_t socket_bind_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }

    sock_bind_t* bind = &req->bind;
    if (sock->ops->bind == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    return sock->ops->bind(sock, bind->addr, bind->addrlen);
}

net_err_t socket_send_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->remote_port == 0 && ipaddr_is_any(&sock->remote_ip))
    {
        return NET_ERR_ADDR_UNSET;
    }
    if (sock->ops->send == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = sock->ops->send(sock, req->data.buf, req->data.len, req->data.flags, &req->data.transferred_len);
    if (err == NET_ERR_NEED_WAIT && sock->send_wait)
    {
        sock_wait_add(sock->send_wait, sock->send_timeout, req);
    }
    return err;
}

net_err_t socket_recv_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->remote_port == 0 && ipaddr_is_any(&sock->remote_ip))
    {
        return NET_ERR_ADDR_UNSET;
    }
    if (sock->ops->recv == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = sock->ops->recv(sock, req->data.buf, req->data.len, req->data.flags, &req->data.transferred_len);
    if (err == NET_ERR_NEED_WAIT && sock->recv_wait)
    {
        sock_wait_add(sock->recv_wait, sock->recv_timeout, req);
    }
    return err;
}

net_err_t socket_listen_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    sock_listen_t* listen = &req->listen;
    if (listen->backlog <= 0)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->ops->listen == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    return sock->ops->listen(sock, listen->backlog);
}

net_err_t socket_accept_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }

    sock_accept_t* accept = &req->accept;
    sock_t* client = NULL;
    if (sock->ops->accept == NULL)
    {
        return NET_ERR_UNIMPLEMENTED;
    }
    net_err_t err = sock->ops->accept(sock, accept->addr, accept->addrlen, &client);
    if (err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_SOCK, "socket accept failed, err=%d", err);
    }
    else if (err == NET_ERR_NEED_WAIT && sock->conn_wait)
    {
        sock_wait_add(sock->conn_wait, sock->recv_timeout, req);
    }
    else if (err == NET_ERR_OK && client)
    {
        const int client_fd = sock_fd_alloc_socket(client);
        if (client_fd < 0)
        {
            sock_dispose(client);
            return NET_ERR_MEM;
        }
        accept->client_fd = client_fd;
    }
    return err;
}

net_err_t socket_destroy_req_in(const func_msg_t* msg)
{
    sock_req_t* req = msg->arg;
    sock_t* sock = sock_fd_get_socket(req->fd);
    if (sock == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    if (sock->ops->destroy)
    {
        sock->ops->destroy(sock);
    }
    sock_fd_release(req->fd);
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
    nlist_init(&sock->epoll_list);
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
    ((sock_t*)sock)->err = err;
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
    x_epoll_sock_wakeup(sock);
    x_select_wakeup();
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
    case SO_REUSEADDR:
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
