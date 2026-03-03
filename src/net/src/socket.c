#include "socket.h"
#include "dbug.h"
#include "exmsg.h"
#include "sock.h"

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
        return -1;
    }
    return req.fd;
}

ssize_t x_sendto(const int fd, const void* buf, size_t len, const int flags, struct x_sockaddr* addr,
                 x_socklen_t addrlen)
{
    if (buf == NULL || addr == NULL || len == 0)
    {
        return -1;
    }

    if (addr->sa_family != AF_INET || addrlen != sizeof(struct sockaddr))
    {
        return -1;
    }

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
        req.wait = NULL;
        req.wait_timeout = 0;

        net_err_t err = exmsg_func_exec(socket_sendto_req_in, &req);
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_sendto_req_in sendto failed");
            return -1;
        }

        if (req.wait && (err = sock_wait_enter(req.wait, req.wait_timeout)) < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_sendto: wait failed, err=%d", err);
            return -1;
        }

        len -= req.data.transferred_len;
        send_buf += req.data.transferred_len;
        total_sent += req.data.transferred_len;
    }
    return total_sent;
}

ssize_t x_recvfrom(const int fd, void* buf, const size_t len, const int flags, struct x_sockaddr* addr,
                   x_socklen_t* addrlen)
{
    if (buf == NULL || addr == NULL || len == 0 || addrlen == NULL)
    {
        return -1;
    }

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
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recvfrom_req_in recvfrom failed");
            return -1;
        }
        if (req.data.transferred_len > 0)
        {
            return req.data.transferred_len;
        }

        // 等待数据到达
        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recvfrom: wait failed, err=%d", err);
            return err;
        }
    }
}

int x_bind(const int fd, struct x_sockaddr* addr, const x_socklen_t addrlen)
{
    if (fd < 0 || addr == NULL || addrlen != sizeof(struct x_sockaddr))
    {
        dbug_error(DBG_MOD_SOCKET, "bind param err");
        return -1;
    }
    if (addr->sa_family != AF_INET)
    {
        dbug_error(DBG_MOD_SOCKET, "family err");
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
        return -1;
    }
    if (req.wait)
    {
        sock_wait_enter(req.wait, req.wait_timeout);
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
        return -1;
    }
    return NET_ERR_OK;
}

int x_accept(const int fd, struct x_sockaddr* addr, x_socklen_t* addrlen)
{
    if (fd < 0 || addr == NULL || addrlen == NULL || *addrlen != sizeof(struct x_sockaddr))
    {
        return -1;
    }
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
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_accept_req_in accept failed");
            return -1;
        }
        if (req.accept.client_fd >= 0)
        {
            return req.accept.client_fd;
        }
        if (req.wait && err == NET_ERR_NEED_WAIT)
        {
            sock_wait_enter(req.wait, req.wait_timeout);
        }
    }
}

int x_connect(const int fd, struct x_sockaddr* addr, const x_socklen_t addrlen)
{
    if (fd < 0 || addr == NULL || addrlen != sizeof(struct x_sockaddr))
    {
        dbug_error(DBG_MOD_SOCKET, "connect param err");
        return -1;
    }

    if (addr->sa_family != AF_INET)
    {
        dbug_error(DBG_MOD_SOCKET, "family err");
        return -1;
    }

    sock_req_t req;
    req.wait = NULL;
    req.fd = fd;
    req.conn.addr = addr;
    req.conn.addrlen = addrlen;

    net_err_t err = exmsg_func_exec(socket_connect_req_in, &req);
    if (err < NET_ERR_OK)
    {
        return -1;
    }
    if (req.wait && err == NET_ERR_NEED_WAIT)
    {
        sock_wait_enter(req.wait, req.wait_timeout);
    }
    return 0;
}

ssize_t x_send(const int fd, const void* buf, size_t len, const int flags)
{
    if (buf == NULL || len == 0)
    {
        return -1;
    }

    uint8_t* send_buf = (uint8_t*)buf;
    ssize_t total_sent = 0;
    while (len > 0)
    {
        sock_req_t req;
        req.fd = fd;
        req.data.buf = send_buf;
        req.data.len = len;
        req.data.flags = flags;
        req.wait = NULL;
        req.wait_timeout = 0;

        net_err_t err = exmsg_func_exec(socket_send_req_in, &req);
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_send_req_in sendto failed");
            return -1;
        }

        if (req.wait && (err = sock_wait_enter(req.wait, req.wait_timeout)) < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_send: wait failed, err=%d", err);
            return -1;
        }

        len -= req.data.transferred_len;
        send_buf += req.data.transferred_len;
        total_sent += req.data.transferred_len;
    }
    return total_sent;
}

ssize_t x_recv(const int fd, void* buf, const size_t len, const int flags)
{
    if (buf == NULL || len == 0)
    {
        return -1;
    }

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
            return 0; // 连接已关闭，返回0表示EOF
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recv_req_in recvfrom failed");
            return -1;
        }
        if (req.data.transferred_len > 0)
        {
            return req.data.transferred_len;
        }

        // 等待数据到达
        err = sock_wait_enter(req.wait, req.wait_timeout);
        if (err == NET_ERR_CLOSE)
        {
            return 0; // 连接已关闭，返回0表示EOF
        }
        if (err < NET_ERR_OK)
        {
            dbug_error(DBG_MOD_SOCKET, "socket_recv: wait failed, err=%d", err);
            return err;
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
    sock_req_t req;
    req.fd = fd;
    req.wait = NULL;
    req.wait_timeout = 0;

    net_err_t err = exmsg_func_exec(socket_close_req_in, &req);
    if (err < NET_ERR_OK)
    {
        return -1;
    }
    if (req.wait && err == NET_ERR_NEED_WAIT)
    {
        sock_wait_enter(req.wait, req.wait_timeout);
        // 销毁socket资源
        exmsg_func_exec(socket_destroy_req_in, &req);
    }
    return 0;
}

int x_setsockopt(const int fd, const int level, int opt_name, const void* opt_val, int opt_len)
{
    if (opt_val == NULL || opt_len == 0)
    {
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
        return -1;
    }
    return req.fd;
}
