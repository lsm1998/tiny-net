#include "socket.h"
#include "dbug.h"
#include "exmsg.h"
#include "sock.h"
#include "epoll.h"
#include "dns.h"
#include "tool.h"

#include <errno.h>

static int socket_err_to_errno(const net_err_t err)
{
    switch (err)
    {
    case NET_ERR_NEED_WAIT:
        return EAGAIN;
    case NET_ERR_MEM:
        return ENOMEM;
    case NET_ERR_INVALID_PARAM:
    case NET_ERR_INVALID_STATE:
    case NET_ERR_STATE:
    case NET_ERR_OPTION:
        return EINVAL;
    case NET_ERR_TIMEOUT:
        return ETIMEDOUT;
    case NET_ERR_FULL:
        return ENOBUFS;
    case NET_ERR_PROTOCOL:
        return EPROTONOSUPPORT;
    case NET_ERR_NO_ROUTE:
        return ENETUNREACH;
    case NET_ERR_PORT_UNREACH:
        return ECONNREFUSED;
    case NET_ERR_ADDR_UNSET:
        return EDESTADDRREQ;
    case NET_ERR_ADDR_IN_USE:
        return EADDRINUSE;
    case NET_ERR_IP_UNREACH:
    case NET_ERR_TARGET_ADDR_MATCH:
    case NET_ERR_ADDR:
        return EHOSTUNREACH;
    case NET_ERR_REST:
        return ECONNRESET;
    case NET_ERR_CLOSE:
        return EPIPE;
    case NET_ERR_UNIMPLEMENTED:
        return ENOSYS;
    default:
        return EIO;
    }
}

static int socket_fail(const net_err_t err)
{
    errno = socket_err_to_errno(err);
    return -1;
}

static int socket_is_nonblock(const int fd)
{
    sock_t* sock = sock_fd_get_socket(fd);
    return sock != NULL && sock->nonblock;
}

static void socket_epoll_recheck(const int fd)
{
    if (sock_fd_type(fd) == X_FD_TYPE_SOCKET)
    {
        x_epoll_fd_recheck(fd);
    }
}

int x_socket(const int family, const int type, const int protocol)
{
    sock_req_t req;
    req.fd = -1;
    req.wait = NULL;
    req.wait_timeout = 0;
    req.create.family = family;
    req.create.type = type;
    req.create.protocol = protocol;
    net_err_t err = exmsg_func_exec(socket_create_req_in, &req);
    if (err != NET_ERR_OK)
    {
        return socket_fail(err);
    }
    return req.fd;
}

ssize_t x_sendto(const int fd, const void* buf, size_t len, const int flags, struct x_sockaddr* addr,
                 x_socklen_t addrlen)
{
    if (buf == NULL || addr == NULL || len == 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (addr->sa_family != AF_INET || addrlen != sizeof(struct sockaddr))
    {
        errno = EINVAL;
        return -1;
    }

    const int nonblock = socket_is_nonblock(fd);
    uint8_t* send_buf = (uint8_t*)buf;
    ssize_t total_sent = 0;
    while (len > 0)
    {
        sock_req_t req;
        req.fd = fd;
        req.data.addrlen = &addrlen;
        req.data.addr = addr;
        req.data.buf = send_buf;
        req.data.len = len;
        req.data.flags = flags;
        req.data.transferred_len = 0;
        req.wait = NULL;
        req.wait_timeout = 0;

        net_err_t err = exmsg_func_exec(socket_sendto_req_in, &req);
        if (err == NET_ERR_NEED_WAIT && nonblock)
        {
            socket_epoll_recheck(fd);
            if (total_sent > 0)
            {
                return total_sent;
            }
            errno = EAGAIN;
            return -1;
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_sendto_req_in sendto failed");
            socket_epoll_recheck(fd);
            return total_sent > 0 ? total_sent : socket_fail(err);
        }

        if (req.wait)
        {
            err = sock_wait_enter(req.wait, req.wait_timeout);
            if (err < NET_ERR_OK)
            {
                dbug_error(DBG_MOD_SOCKET, "socket_sendto: wait failed, err=%d", err);
                socket_epoll_recheck(fd);
                return total_sent > 0 ? total_sent : socket_fail(err);
            }
        }

        if (req.data.transferred_len <= 0)
        {
            socket_epoll_recheck(fd);
            if (total_sent > 0)
            {
                return total_sent;
            }
            errno = EAGAIN;
            return -1;
        }

        len -= req.data.transferred_len;
        send_buf += req.data.transferred_len;
        total_sent += req.data.transferred_len;
    }
    socket_epoll_recheck(fd);
    return total_sent;
}

ssize_t x_recvfrom(const int fd, void* buf, const size_t len, const int flags, struct x_sockaddr* addr,
                   x_socklen_t* addrlen)
{
    if (buf == NULL || addr == NULL || len == 0 || addrlen == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    const int nonblock = socket_is_nonblock(fd);
    while (true)
    {
        sock_req_t req;
        req.wait = NULL;
        req.wait_timeout = 0;
        req.fd = fd;
        req.data.addrlen = addrlen;
        req.data.addr = addr;
        req.data.buf = buf;
        req.data.len = len;
        req.data.flags = flags;
        req.data.transferred_len = 0;

        net_err_t err = exmsg_func_exec(socket_recvfrom_req_in, &req);
        if (err == NET_ERR_NEED_WAIT && nonblock)
        {
            socket_epoll_recheck(fd);
            errno = EAGAIN;
            return -1;
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recvfrom_req_in recvfrom failed");
            socket_epoll_recheck(fd);
            return socket_fail(err);
        }
        if (req.data.transferred_len > 0)
        {
            socket_epoll_recheck(fd);
            return req.data.transferred_len;
        }

        if (req.wait == NULL)
        {
            socket_epoll_recheck(fd);
            errno = EAGAIN;
            return -1;
        }

        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recvfrom: wait failed, err=%d", err);
            socket_epoll_recheck(fd);
            return socket_fail(err);
        }
    }
}

int x_bind(const int fd, struct x_sockaddr* addr, const x_socklen_t addrlen)
{
    if (fd < 0 || addr == NULL || addrlen != sizeof(struct x_sockaddr))
    {
        dbug_error(DBG_MOD_SOCKET, "bind param err");
        errno = EINVAL;
        return -1;
    }
    if (addr->sa_family != AF_INET)
    {
        dbug_error(DBG_MOD_SOCKET, "family err");
        errno = EINVAL;
        return -1;
    }

    sock_req_t req;
    req.wait = NULL;
    req.fd = fd;
    req.bind.addr = addr;
    req.bind.addrlen = addrlen;

    net_err_t err = exmsg_func_exec(socket_bind_req_in, &req);
    if (err != NET_ERR_OK)
    {
        return socket_fail(err);
    }
    if (req.wait)
    {
        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err < NET_ERR_OK)
        {
            return socket_fail(err);
        }
    }
    return 0;
}

int x_listen(const int fd, const int backlog)
{
    sock_req_t req;
    req.fd = fd;
    req.wait = NULL;
    req.wait_timeout = 0;
    req.listen.backlog = backlog;
    net_err_t err = exmsg_func_exec(socket_listen_req_in, &req);
    if (err != NET_ERR_OK)
    {
        return socket_fail(err);
    }
    return 0;
}

int x_accept(const int fd, struct x_sockaddr* addr, x_socklen_t* addrlen)
{
    if (fd < 0 || addr == NULL || addrlen == NULL || *addrlen != sizeof(struct x_sockaddr))
    {
        errno = EINVAL;
        return -1;
    }
    const int nonblock = socket_is_nonblock(fd);
    while (true)
    {
        sock_req_t req;
        req.fd = fd;
        req.wait = NULL;
        req.wait_timeout = 0;
        req.accept.addr = addr;
        req.accept.addrlen = addrlen;
        req.accept.client_fd = -1;
        net_err_t err = exmsg_func_exec(socket_accept_req_in, &req);
        if (err == NET_ERR_NEED_WAIT && nonblock)
        {
            socket_epoll_recheck(fd);
            errno = EAGAIN;
            return -1;
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_accept_req_in accept failed");
            socket_epoll_recheck(fd);
            return socket_fail(err);
        }
        if (req.accept.client_fd >= 0)
        {
            socket_epoll_recheck(fd);
            return req.accept.client_fd;
        }
        if (req.wait && err == NET_ERR_NEED_WAIT)
        {
            err = sock_wait_enter(req.wait, req.wait_timeout);
            if (err < NET_ERR_OK)
            {
                socket_epoll_recheck(fd);
                return socket_fail(err);
            }
        }
        else
        {
            socket_epoll_recheck(fd);
            errno = EAGAIN;
            return -1;
        }
    }
}

int x_connect(const int fd, struct x_sockaddr* addr, const x_socklen_t addrlen)
{
    if (fd < 0 || addr == NULL || addrlen != sizeof(struct x_sockaddr))
    {
        dbug_error(DBG_MOD_SOCKET, "connect param err");
        errno = EINVAL;
        return -1;
    }

    if (addr->sa_family != AF_INET)
    {
        dbug_error(DBG_MOD_SOCKET, "family err");
        errno = EINVAL;
        return -1;
    }

    sock_req_t req;
    req.wait = NULL;
    req.fd = fd;
    req.conn.addr = addr;
    req.conn.addrlen = addrlen;

    const int nonblock = socket_is_nonblock(fd);
    net_err_t err = exmsg_func_exec(socket_connect_req_in, &req);
    if (err == NET_ERR_NEED_WAIT && nonblock)
    {
        errno = EINPROGRESS;
        return -1;
    }
    if (err < NET_ERR_OK)
    {
        return socket_fail(err);
    }
    if (req.wait && err == NET_ERR_NEED_WAIT)
    {
        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err < NET_ERR_OK)
        {
            socket_epoll_recheck(fd);
            return socket_fail(err);
        }
    }
    socket_epoll_recheck(fd);
    return 0;
}

ssize_t x_send(const int fd, const void* buf, size_t len, const int flags)
{
    if (buf == NULL || len == 0)
    {
        errno = EINVAL;
        return -1;
    }

    const int nonblock = socket_is_nonblock(fd);
    uint8_t* send_buf = (uint8_t*)buf;
    ssize_t total_sent = 0;
    while (len > 0)
    {
        sock_req_t req;
        req.fd = fd;
        req.data.buf = send_buf;
        req.data.len = len;
        req.data.flags = flags;
        req.data.transferred_len = 0;
        req.wait = NULL;
        req.wait_timeout = 0;

        net_err_t err = exmsg_func_exec(socket_send_req_in, &req);
        if (err == NET_ERR_NEED_WAIT && nonblock)
        {
            socket_epoll_recheck(fd);
            if (total_sent > 0)
            {
                return total_sent;
            }
            errno = EAGAIN;
            return -1;
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_send_req_in sendto failed");
            socket_epoll_recheck(fd);
            return total_sent > 0 ? total_sent : socket_fail(err);
        }

        if (req.wait)
        {
            err = sock_wait_enter(req.wait, req.wait_timeout);
            if (err < NET_ERR_OK)
            {
                dbug_error(DBG_MOD_SOCKET, "socket_send: wait failed, err=%d", err);
                socket_epoll_recheck(fd);
                return total_sent > 0 ? total_sent : socket_fail(err);
            }
        }

        if (req.data.transferred_len <= 0)
        {
            socket_epoll_recheck(fd);
            if (total_sent > 0)
            {
                return total_sent;
            }
            errno = EAGAIN;
            return -1;
        }

        len -= req.data.transferred_len;
        send_buf += req.data.transferred_len;
        total_sent += req.data.transferred_len;
    }
    socket_epoll_recheck(fd);
    return total_sent;
}

ssize_t x_recv(const int fd, void* buf, const size_t len, const int flags)
{
    if (buf == NULL || len == 0)
    {
        errno = EINVAL;
        return -1;
    }

    const int nonblock = socket_is_nonblock(fd);
    while (true)
    {
        sock_req_t req;
        req.wait = NULL;
        req.wait_timeout = 0;
        req.fd = fd;
        req.data.buf = buf;
        req.data.len = len;
        req.data.flags = flags;
        req.data.transferred_len = 0;

        net_err_t err = exmsg_func_exec(socket_recv_req_in, &req);
        if (err == NET_ERR_CLOSE)
        {
            socket_epoll_recheck(fd);
            return 0; // 连接已关闭，返回0表示EOF
        }
        if (err == NET_ERR_NEED_WAIT && nonblock)
        {
            socket_epoll_recheck(fd);
            errno = EAGAIN;
            return -1;
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recv_req_in recvfrom failed");
            socket_epoll_recheck(fd);
            return socket_fail(err);
        }
        if (req.data.transferred_len > 0)
        {
            socket_epoll_recheck(fd);
            return req.data.transferred_len;
        }

        if (req.wait == NULL)
        {
            socket_epoll_recheck(fd);
            errno = EAGAIN;
            return -1;
        }

        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err == NET_ERR_CLOSE)
        {
            socket_epoll_recheck(fd);
            return 0; // 连接已关闭，返回0表示EOF
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recv: wait failed, err=%d", err);
            socket_epoll_recheck(fd);
            return socket_fail(err);
        }
    }
}

ssize_t x_read(const int fd, void* buf, const size_t len)
{
    return x_recv(fd, buf, len, 0);
}

ssize_t x_write(const int fd, const void* buf, const size_t len)
{
    return x_send(fd, buf, len, 0);
}

int x_close(const int fd)
{
    const x_fd_type_t fd_type = sock_fd_type(fd);
    if (fd_type == X_FD_TYPE_EPOLL)
    {
        return x_epoll_close(fd);
    }
    if (fd_type != X_FD_TYPE_SOCKET)
    {
        errno = EBADF;
        return -1;
    }

    sock_req_t req;
    req.fd = fd;
    req.wait = NULL;
    req.wait_timeout = 0;

    net_err_t err = exmsg_func_exec(socket_close_req_in, &req);
    if (err < NET_ERR_OK)
    {
        return socket_fail(err);
    }
    if (req.wait && err == NET_ERR_NEED_WAIT)
    {
        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err < NET_ERR_OK && err != NET_ERR_CLOSE)
        {
            return socket_fail(err);
        }
        // 销毁socket资源
        err = exmsg_func_exec(socket_destroy_req_in, &req);
        if (err < NET_ERR_OK)
        {
            return socket_fail(err);
        }
    }
    return 0;
}

int x_setsockopt(const int fd, const int level, int opt_name, const void* opt_val, int opt_len)
{
    if (opt_val == NULL || opt_len == 0)
    {
        errno = EINVAL;
        return -1;
    }
    sock_req_t req;
    req.fd = fd;
    req.wait = NULL;
    req.wait_timeout = 0;
    req.opt.level = level;
    req.opt.opt_name = opt_name;
    req.opt.opt_val = opt_val;
    req.opt.opt_len = opt_len;

    net_err_t err = exmsg_func_exec(socket_setsockopt_req_in, &req);
    if (err != NET_ERR_OK)
    {
        return socket_fail(err);
    }
    return 0;
}

int x_getaddrinfo(const char* node, const char* service, const struct x_addrinfo* hints, struct x_addrinfo** res)
{
    if (node == NULL || res == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    // if (hints && hints->ai_family != 0 && hints->ai_family != AF_INET)
    // {
    //     return NET_ERR_ADDR;
    // }

    *res = NULL;

    uint16_t port = 0;
    if (service && *service)
    {
        uint32_t port_value = 0;
        for (const char* c = service; *c; c++)
        {
            if (*c < '0' || *c > '9')
            {
                return NET_ERR_INVALID_PARAM;
            }
            port_value = port_value * 10 + (uint32_t)(*c - '0');
            if (port_value > 65535)
            {
                return NET_ERR_INVALID_PARAM;
            }
        }
        port = (uint16_t)port_value;
    }

    dns_req_t* req = dns_alloc_req();
    if (req == NULL)
    {
        return NET_ERR_MEM;
    }

    plat_strncpy(req->domain, node, DNS_DOMAIN_MAX_LEN);
    req->domain[DNS_DOMAIN_MAX_LEN - 1] = '\0';
    ipaddr_set_any(&req->ipaddr);
    req->err = NET_ERR_OK;

    net_err_t err = exmsg_func_exec(dns_query_req_in, req);
    if (err < NET_ERR_OK)
    {
        goto dns_req_err;
    }
    if (err == NET_ERR_NEED_WAIT && req->wait_sem != SYS_SEM_INVALID && sys_sem_wait(req->wait_sem, 0) < 0)
    {
        dbug_error(DBG_MOD_DNS, "x_getaddrinfo: wait failed, err=%d", err);
        err = NET_ERR_TIMEOUT;
        goto dns_req_err;
    }

    if (req->err < NET_ERR_OK)
    {
        dbug_error(DBG_MOD_DNS, "x_getaddrinfo: dns query failed, err=%d", req->err);
        err = req->err;
        goto dns_req_err;
    }

    // 构造结果
    struct x_addrinfo* ai = malloc(sizeof(struct x_addrinfo));
    if (ai == NULL)
    {
        err = NET_ERR_MEM;
        goto dns_req_err;
    }

    ai->ai_flags = hints ? hints->ai_flags : 0;
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints ? hints->ai_socktype : 0;
    ai->ai_protocol = hints ? hints->ai_protocol : 0;
    ai->ai_addrlen = sizeof(struct x_sockaddr_in);
    ai->ai_addr = (struct x_sockaddr*)malloc(sizeof(struct x_sockaddr_in));
    if (ai->ai_addr == NULL)
    {
        free(ai);
        err = NET_ERR_MEM;
        goto dns_req_err;
    }

    struct x_sockaddr_in* addr_in = (struct x_sockaddr_in*)ai->ai_addr;
    plat_memset(addr_in, 0, sizeof(struct x_sockaddr_in));
    addr_in->sin_len = sizeof(struct x_sockaddr_in);
    addr_in->sin_family = AF_INET;
    addr_in->sin_port = x_htons(port);
    ipaddr_to_buf(&req->ipaddr, addr_in->sin_addr.addr_array);

    ai->ai_canonname = NULL;
    ai->ai_next = NULL;
    *res = ai;
    err = NET_ERR_OK;

dns_req_err:
    dns_free_req(req);
    return err;
}

void x_freeaddrinfo(struct x_addrinfo* res)
{
    while (res)
    {
        struct x_addrinfo* next = res->ai_next;
        if (res->ai_canonname)
        {
            free(res->ai_canonname);
        }
        if (res->ai_addr)
        {
            free(res->ai_addr);
        }
        free(res);
        res = next;
    }
}
