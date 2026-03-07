#include <stdio.h>
#include "net_api.h"
#include "epoll.h"
#include "common.h"
#include "dbug_module.h"

#define PORT 9999
#define MAX_EVENTS 1024
#define BUFFER_SIZE 1024

// 设置非阻塞
int set_nonblocking(const int fd)
{
    int opt_val = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NONBLOCK, &opt_val, sizeof(opt_val));
}

int main()
{
    dbug_module_enable_only(DBG_MOD_TCP);
    if (tiny_net_init() != NET_ERR_OK)
    {
        fprintf(stderr, "tiny_net_init failed\n");
        return 1;
    }

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 创建 socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    if (listen(listen_fd, 128) < 0)
    {
        perror("listen");
        exit(1);
    }

    set_nonblocking(listen_fd);

    // 创建 epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
    {
        perror("epoll_create1");
        exit(1);
    }

    struct epoll_event ev, events[MAX_EVENTS];

    // 注册监听 socket
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

    printf("epoll server listening on port %d...\n", PORT);

    while (1)
    {
        int n_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, 2000);
        if (n_fds < 0)
        {
            perror("epoll_wait");
            break;
        }
        printf("epoll_wait returned %d events\n", n_fds);

        for (int i = 0; i < n_fds; i++)
        {
            int fd = events[i].data.fd;

            // 新连接
            if (fd == listen_fd)
            {
                while (1)
                {
                    int conn_fd = accept(listen_fd,
                                         (struct sockaddr*)&client_addr,
                                         &client_len);

                    if (conn_fd < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        perror("accept");
                        break;
                    }

                    set_nonblocking(conn_fd);

                    printf("New client: %s:%d\n",
                           inet_ntoa(client_addr.sin_addr),
                           ntohs(client_addr.sin_port));

                    ev.events = EPOLLIN;
                    ev.data.fd = conn_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);
                }
            }
            // 客户端数据
            else
            {
                char buffer[BUFFER_SIZE];

                while (1)
                {
                    int n = read(fd, buffer, sizeof(buffer));

                    if (n > 0)
                    {
                        write(fd, buffer, n); // echo
                    }
                    else if (n == 0)
                    {
                        printf("Client disconnected\n");
                        close(fd);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                        break;
                    }
                    else
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        perror("read");
                        close(fd);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                        break;
                    }
                }
            }
        }
    }

    close(listen_fd);
    close(epoll_fd);
    return 0;
}
