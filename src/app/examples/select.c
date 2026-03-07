#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "net_api.h"
#include "select.h"
#include "common.h"
#include "dbug_module.h"

#define PORT 9999
#define BUFFER_SIZE 1024

static int set_nonblocking(const int fd)
{
    int opt_val = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NONBLOCK, &opt_val, sizeof(opt_val));
}

static void update_max_fd(const fd_set* master_set, int* max_fd)
{
    while (*max_fd >= 0 && !FD_ISSET(*max_fd, master_set))
    {
        (*max_fd)--;
    }
}

int main(void)
{
    dbug_module_enable_only(DBG_MOD_TCP);
    if (tiny_net_init() != NET_ERR_OK)
    {
        fprintf(stderr, "tiny_net_init failed\n");
        return 1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (set_nonblocking(listen_fd) < 0)
    {
        perror("set_nonblocking listen_fd");
        close(listen_fd);
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 128) < 0)
    {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    fd_set master_set;
    FD_ZERO(&master_set);
    FD_SET(listen_fd, &master_set);
    int max_fd = listen_fd;

    printf("select server listening on port %d...\n", PORT);

    while (1)
    {
        fd_set read_set = master_set;

        timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        int ready = select(max_fd + 1, &read_set, NULL, NULL, &timeout);
        if (ready < 0)
        {
            perror("select");
            break;
        }
        for (int fd = 0; fd <= max_fd && ready > 0; ++fd)
        {
            if (!FD_ISSET(fd, &read_set))
            {
                continue;
            }
            ready--;

            if (fd == listen_fd)
            {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);

                while (1)
                {
                    int conn_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
                    if (conn_fd < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            break;
                        }
                        perror("accept");
                        break;
                    }

                    if (set_nonblocking(conn_fd) < 0)
                    {
                        perror("set_nonblocking conn_fd");
                        close(conn_fd);
                        continue;
                    }

                    printf("New client: %s:%d\n",
                           inet_ntoa(client_addr.sin_addr),
                           ntohs(client_addr.sin_port));

                    FD_SET(conn_fd, &master_set);
                    if (conn_fd > max_fd)
                    {
                        max_fd = conn_fd;
                    }
                }
            }
            else
            {
                char buffer[BUFFER_SIZE];

                while (1)
                {
                    int n = read(fd, buffer, sizeof(buffer));
                    if (n > 0)
                    {
                        write(fd, buffer, n);
                    }
                    else if (n == 0)
                    {
                        printf("Client disconnected\n");
                        close(fd);
                        FD_CLR(fd, &master_set);
                        if (fd == max_fd)
                        {
                            update_max_fd(&master_set, &max_fd);
                        }
                        break;
                    }
                    else
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            break;
                        }
                        perror("read");
                        close(fd);
                        FD_CLR(fd, &master_set);
                        if (fd == max_fd)
                        {
                            update_max_fd(&master_set, &max_fd);
                        }
                        break;
                    }
                }
            }
        }
    }

    close(listen_fd);
    return 0;
}
