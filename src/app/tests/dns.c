#include "net_api.h"
#include "common.h"

int main()
{
    tiny_net_init();
    char* dest = "www.baidu.com";
    // char* dest = "localhost";
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;

    int status = getaddrinfo(dest, NULL, &hints, &res);
    if (status != 0)
        return -1;

    if (res->ai_addr == NULL)
    {
        printf("ai_addr is NULL\n");
        return -1;
    }

    printf("Address for %s: %s\n", dest, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
    return 0;
}
