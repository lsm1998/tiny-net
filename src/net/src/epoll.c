#include "epoll.h"

int x_epoll_create()
{
    return -1;
}

int x_epoll_create1(int flags)
{
    return -1;
}

int x_epoll_ctl(int epoll_fd, int op, int fd, x_epoll_event_t* event)
{
    return -1;
}

int x_epoll_wait(int epoll_fd, x_epoll_event_t* events, int max_events, int timeout)
{
    return -1;
}
