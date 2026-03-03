#include "ping.h"
#include "tool.h"
#include "socket.h"
#include "net_api.h"
#include "sys.h"

#define ECHO_ID 0x1234

int get_host(const char* dest, char* ip_str, const size_t ip_str_size)
{
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = 0; // 不限制套接字类型

    int status = getaddrinfo(dest, NULL, &hints, &res);
    if (status != 0)
        return -1;

    for (struct addrinfo* p = res; p != NULL; p = p->ai_next)
    {
        if (p->ai_family == AF_INET)
        {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            if (inet_ntop(AF_INET, &ipv4->sin_addr,
                          ip_str, ip_str_size) == NULL)
            {
                perror("inet_ntop");
                freeaddrinfo(res);
                return -1;
            }

            freeaddrinfo(res);
            return 0;
        }
    }

    freeaddrinfo(res);
    return -1;
}

void ping_run(ping_t* ping, const char* dest, const int count, const int size, const int interval, const int timeout)
{
    char dest_ip[16];
    if (inet_pton(AF_INET, dest, dest_ip) > 0) // 直接是IP地址
    {
        strncpy(dest_ip, dest, sizeof(dest_ip));
    }
    else if (get_host(dest, dest_ip, sizeof(dest_ip)) < 0) // 解析域名失败
    {
        plat_printf("Invalid destination: %s\n", dest);
        return;
    }

    static uint16_t seq_id = ECHO_ID;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
    {
        plat_printf("socket creation failed\n");
        return;
    }

    timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dest_addr;
    plat_memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // if (connect(fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
    // {
    //     plat_printf("connect failed\n");
    //     close(fd);
    //     return;
    // }

    // 填充数据部分
    int fill_size = size < PING_BUFFER_SIZE ? size : PING_BUFFER_SIZE;
    for (int i = 0; i < fill_size; ++i)
    {
        ping->request.data[i] = (char)(i & 0xFF);
    }

    int total_size = (int)sizeof(icmp_v4_header_t) + fill_size;

    int loss = 0;

    plat_printf("PING %s (%s): %d data bytes\n", dest_ip, dest_ip, fill_size);

    for (int i = 0; i < count; ++i)
    {
        net_time_t start_time;
        sys_time_curr(&start_time);

        // 构建ICMP请求报文
        ping->request.icmp_header.type = ICMP_V4_TYPE_ECHO_REQUEST;
        ping->request.icmp_header.code = 0;
        ping->request.icmp_header.checksum = 0;
        ping->request.icmp_header.echo.id = htons(seq_id);
        ping->request.icmp_header.echo.seq = htons(i);

        ping->request.icmp_header.checksum = checksum16((uint8_t*)&ping->request.icmp_header,
                                                        sizeof(icmp_v4_header_t) + fill_size,
                                                        0, true);

        // 发送请求报文
        // ssize_t n = send(fd, &ping->request, total_size, 0);
        ssize_t n = sendto(fd, &ping->request, total_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if (n < 0)
        {
            plat_printf("sendto failed\n");
            continue;
        }

        while (true)
        {
            // 接收响应报文
            socklen_t addrlen = sizeof(dest_addr);
            ssize_t recv_size = recvfrom(fd, &ping->reply, sizeof(ping->reply), 0, (struct sockaddr*)&dest_addr,
                                         &addrlen);
            if (recv_size < 0)
            {
                plat_printf("Request timed out for icmp_seq %d\n", i);
                loss++;
                break;
            }

            // 解析响应报文
            icmp_v4_header_t* icmp_header = &ping->reply.icmp_header;
            if (icmp_header->type == ICMP_V4_TYPE_ECHO_REPLY &&
                ntohs(icmp_header->echo.id) == seq_id &&
                ntohs(icmp_header->echo.seq) == i)
            {
                net_time_t end_time;
                sys_time_curr(&end_time);
                double rtt = (double)(end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                    (double)(end_time.tv_usec - start_time.tv_usec) / 1000.0;

                plat_printf("%d bytes from %s: icmp_seq=%d ttl=%d time:%.3f ms\n",
                            (int)(recv_size - sizeof(ipv4_header_t)),
                            dest_ip,
                            ntohs(icmp_header->echo.seq),
                            ping->reply.ip_header.ttl, rtt);
                break;
            }
        }

        // 等待指定间隔
        sys_sleep(interval);
    }

    // 统计丢包率
    int received = count - loss;
    float loss_rate = ((float)loss / (float)count) * 100.0f;
    plat_printf("\n--- %s ping statistics ---\n", dest_ip);
    plat_printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
                count, received, loss_rate);
    if (close(fd) != 0)
    {
        plat_printf("socket close failed\n");
    }
    else
    {
        plat_printf("socket closed\n");
    }
}
