#include "net_api.h"
#include "common.h"
#include "dbug_module.h"

int main()
{
    dbug_module_enable_only(DBG_MOD_TCP);
    tiny_net_init();

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
    {
        perror("socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9999);
    server_addr.sin_addr.s_addr = inet_addr("192.168.100.95");

    if (bind(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("bind failed\n");
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0)
    {
        printf("listen failed\n");
        close(fd);
        return -1;
    }

    for (;;)
    {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        int client_fd = accept(fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0)
        {
            printf("accept failed\n");
            break;
        }

        while (true)
        {
            char buffer[1024];
            plat_memset(buffer, 0, sizeof(buffer));
            ssize_t recv_len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
            if (recv_len < 0)
            {
                printf("recv failed\n");
                close(client_fd);
                break;
            }
            if (recv_len == 0)
            {
                printf("client closed connection\n");
                close(client_fd);
                break;
            }
            // 回显数据
            buffer[recv_len] = '\0';
            printf("Received from client: %s\n", buffer);
            if (send(client_fd, buffer, recv_len, 0) < 0)
            {
                printf("send failed\n");
            }
        }
    }
    return 0;
}
