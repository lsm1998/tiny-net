#include "epoll.h"

#include "dbug.h"
#include "sys.h"
#include "rb_tree.h"

static x_epoll_t epoll_tbl[EPOLL_MAX_INSTANCES];
static sys_mutex_t epoll_sock_lock = SYS_MUTEX_INVALID;

static uint32_t epoll_events_from_poll(const uint32_t poll_events)
{
    uint32_t epoll_events = 0;
    if (poll_events & X_POLLIN)
    {
        epoll_events |= EPOLLIN;
    }
    if (poll_events & X_POLLOUT)
    {
        epoll_events |= EPOLLOUT;
    }
    if (poll_events & X_POLLERR)
    {
        epoll_events |= EPOLLERR;
    }
    if (poll_events & X_POLLHUP)
    {
        epoll_events |= EPOLLHUP;
    }
    return epoll_events;
}

static void epoll_item_reset(x_epoll_item_t* item)
{
    item->in_use = 0;
    item->fd = -1;
    item->events = 0;
    item->last_ready = 0;
    item->ready_events = 0;
    item->queued = 0;
    item->on_sock_list = 0;
    item->sock = NULL;
    item->epoll = NULL;
    item->data.ptr = NULL;
    rb_node_init(&item->rb_node);
    nlist_node_init(&item->ready_node);
    nlist_node_init(&item->sock_node);
}

static x_epoll_t* epoll_get(const int epoll_fd)
{
    x_epoll_t* epoll = sock_fd_get_epoll(epoll_fd);
    if (epoll == NULL || !epoll->in_use || epoll->fd != epoll_fd)
    {
        dbug_error(DBG_MOD_TCP, "invalid epoll fd %d", epoll_fd);
        return NULL;
    }
    return epoll;
}

static int epoll_prepare_slot(x_epoll_t* epoll)
{
    if (epoll_sock_lock == SYS_MUTEX_INVALID)
    {
        epoll_sock_lock = sys_mutex_create();
        if (epoll_sock_lock == SYS_MUTEX_INVALID)
        {
            dbug_error(DBG_MOD_TCP, "failed to create epoll socket lock");
            return -1;
        }
    }

    if (epoll->wait_sem == SYS_SEM_INVALID)
    {
        epoll->wait_sem = sys_sem_create(0);
        if (epoll->wait_sem == SYS_SEM_INVALID)
        {
            dbug_error(DBG_MOD_TCP, "failed to create epoll wait semaphore");
            return -1;
        }
    }
    if (epoll->locker == SYS_MUTEX_INVALID)
    {
        epoll->locker = sys_mutex_create();
        if (epoll->locker == SYS_MUTEX_INVALID)
        {
            dbug_error(DBG_MOD_TCP, "failed to create epoll locker mutex");
            return -1;
        }
    }
    return 0;
}

static void epoll_notify_waiters(const x_epoll_t* epoll)
{
    if (epoll == NULL || epoll->wait_sem == SYS_SEM_INVALID)
    {
        return;
    }

    int waiters = 0;
    sys_mutex_lock(epoll->locker);
    waiters = epoll->waiters;
    sys_mutex_unlock(epoll->locker);

    while (waiters-- > 0)
    {
        sys_sem_notify(epoll->wait_sem);
    }
}

static x_epoll_item_t* epoll_item_find_locked(const x_epoll_t* epoll, const int fd)
{
    rb_node_t* node = epoll->interest_tree.root;
    while (node)
    {
        x_epoll_item_t* item = nlist_entry(node, x_epoll_item_t, rb_node);
        if (fd < item->fd)
        {
            node = node->left;
        }
        else if (fd > item->fd)
        {
            node = node->right;
        }
        else
        {
            return item;
        }
    }
    return NULL;
}

static int epoll_item_insert_locked(x_epoll_t* epoll, x_epoll_item_t* item)
{
    rb_node_t** link = &epoll->interest_tree.root;
    rb_node_t* parent = NULL;

    while (*link)
    {
        x_epoll_item_t* curr = nlist_entry(*link, x_epoll_item_t, rb_node);
        if (curr == NULL)
        {
            break;
        }
        parent = *link;
        if (item->fd < curr->fd)
        {
            link = &(*link)->left;
        }
        else if (item->fd > curr->fd)
        {
            link = &(*link)->right;
        }
        else
        {
            return -1;
        }
    }

    rb_link_node(&epoll->interest_tree, parent, link, &item->rb_node);
    return 0;
}

static x_epoll_item_t* epoll_item_alloc_locked(x_epoll_t* epoll)
{
    for (int i = 0; i < EPOLL_MAX_FDS; ++i)
    {
        if (!epoll->items[i].in_use)
        {
            return &epoll->items[i];
        }
    }
    return NULL;
}

static uint32_t epoll_item_poll(const x_epoll_item_t* item)
{
    if (item->sock == NULL || item->sock->ops == NULL || item->sock->ops->poll == NULL)
    {
        return 0;
    }
    uint32_t ready = epoll_events_from_poll(item->sock->ops->poll(item->sock));
    ready &= item->events | EPOLLERR | EPOLLHUP;
    return ready;
}

static int epoll_ready_remove_locked(x_epoll_t* epoll, x_epoll_item_t* item)
{
    if (!item->queued)
    {
        return 0;
    }

    nlist_remove(&epoll->ready_list, &item->ready_node);
    nlist_node_init(&item->ready_node);
    item->queued = 0;
    item->ready_events = 0;
    return 1;
}

static int epoll_ready_push_locked(x_epoll_t* epoll, x_epoll_item_t* item, const uint32_t ready, const int append)
{
    if (ready == 0)
    {
        return 0;
    }

    if (item->queued)
    {
        item->ready_events = append ? (item->ready_events | ready) : ready;
        return 0;
    }

    item->ready_events = ready;
    item->queued = 1;
    nlist_insert_last(&epoll->ready_list, &item->ready_node);
    return 1;
}

static int epoll_item_sync_locked(x_epoll_item_t* item)
{
    x_epoll_t* epoll = item->epoll;
    if (epoll == NULL || !item->in_use || epoll->closed)
    {
        return 0;
    }

    const uint32_t ready = epoll_item_poll(item);
    if (item->events & EPOLLET)
    {
        const uint32_t new_ready = ready & ~item->last_ready;
        item->last_ready = ready;

        if (ready == 0)
        {
            epoll_ready_remove_locked(epoll, item);
            return 0;
        }

        return epoll_ready_push_locked(epoll, item, new_ready, 1);
    }

    item->last_ready = ready;
    if (ready == 0)
    {
        epoll_ready_remove_locked(epoll, item);
        return 0;
    }

    return epoll_ready_push_locked(epoll, item, ready, 0);
}

static x_epoll_item_t* epoll_ready_pop_locked(x_epoll_t* epoll, uint32_t* ready)
{
    nlist_node_t* node = nlist_remove_first(&epoll->ready_list);
    if (node == NULL)
    {
        return NULL;
    }

    x_epoll_item_t* item = nlist_entry(node, x_epoll_item_t, ready_node);
    *ready = item->ready_events;
    item->ready_events = 0;
    item->queued = 0;
    nlist_node_init(&item->ready_node);
    return item;
}

static void epoll_item_remove_locked(x_epoll_t* epoll, x_epoll_item_t* item, const bool sock_lock_held)
{
    if (!item->in_use)
    {
        return;
    }

    epoll_ready_remove_locked(epoll, item);
    rb_erase(&epoll->interest_tree, &item->rb_node);

    if (sock_lock_held && item->on_sock_list && item->sock)
    {
        nlist_remove(&item->sock->epoll_list, &item->sock_node);
        nlist_node_init(&item->sock_node);
        item->on_sock_list = 0;
    }

    --epoll->count;
    epoll_item_reset(item);
}

static int epoll_drain_ready_locked(x_epoll_t* epoll, x_epoll_event_t* events, const int max_events)
{
    x_epoll_item_t* dispatched[EPOLL_MAX_FDS];
    int dispatched_count = 0;
    const int limit = max_events > EPOLL_MAX_FDS ? EPOLL_MAX_FDS : max_events;

    while (dispatched_count < limit)
    {
        uint32_t ready = 0;
        x_epoll_item_t* item = epoll_ready_pop_locked(epoll, &ready);
        if (item == NULL)
        {
            break;
        }

        dispatched[dispatched_count] = item;
        events[dispatched_count].events = ready;
        events[dispatched_count].data = item->data;
        ++dispatched_count;
    }

    for (int i = 0; i < dispatched_count; ++i)
    {
        epoll_item_sync_locked(dispatched[i]);
    }

    return dispatched_count;
}

int x_epoll_create(void)
{
    return x_epoll_create1(0);
}

int x_epoll_create1(const int flags)
{
    if (flags != 0)
    {
        dbug_error(DBG_MOD_TCP, "unsupported epoll flags: %d", flags);
        return -1;
    }

    for (int i = 0; i < EPOLL_MAX_INSTANCES; ++i)
    {
        x_epoll_t* epoll = &epoll_tbl[i];
        if (epoll->in_use)
        {
            continue;
        }

        if (epoll_prepare_slot(epoll) < 0)
        {
            return -1;
        }

        const int fd = sock_fd_alloc_epoll(epoll);
        if (fd < 0)
        {
            dbug_error(DBG_MOD_TCP, "failed to allocate fd for epoll instance");
            return -1;
        }

        epoll->fd = fd;
        epoll->in_use = 1;
        epoll->closed = 0;
        epoll->waiters = 0;
        epoll->count = 0;
        rb_tree_init(&epoll->interest_tree);
        nlist_init(&epoll->ready_list);
        for (int j = 0; j < EPOLL_MAX_FDS; ++j)
        {
            epoll_item_reset(&epoll->items[j]);
        }
        return fd;
    }

    dbug_error(DBG_MOD_TCP, "maximum number of epoll instances reached");
    return -1;
}

int x_epoll_ctl(const int epoll_fd, const int op, const int fd, const x_epoll_event_t* event)
{
    x_epoll_t* epoll = epoll_get(epoll_fd);
    if (epoll == NULL)
    {
        return -1;
    }
    if (sock_fd_type(fd) != X_FD_TYPE_SOCKET)
    {
        dbug_error(DBG_MOD_TCP, "fd %d is not a socket", fd);
        return -1;
    }

    sock_t* sock = sock_fd_get_socket(fd);
    if (sock == NULL)
    {
        dbug_error(DBG_MOD_TCP, "socket for fd %d not found", fd);
        return -1;
    }

    int should_notify = 0;

    sys_mutex_lock(epoll_sock_lock);
    sys_mutex_lock(epoll->locker);

    x_epoll_item_t* item = epoll_item_find_locked(epoll, fd);
    switch (op)
    {
    case EPOLL_CTL_ADD:
        if (event == NULL)
        {
            dbug_error(DBG_MOD_TCP, "event cannot be NULL for EPOLL_CTL_ADD");
            goto ctl_fail;
        }
        if (item != NULL)
        {
            dbug_error(DBG_MOD_TCP, "fd %d is already registered in epoll instance %d", fd, epoll_fd);
            goto ctl_fail;
        }
        if (epoll->count >= EPOLL_MAX_FDS)
        {
            dbug_error(DBG_MOD_TCP, "maximum number of fds in epoll instance %d reached", epoll_fd);
            goto ctl_fail;
        }

        item = epoll_item_alloc_locked(epoll);
        if (item == NULL)
        {
            dbug_error(DBG_MOD_TCP, "no available slots for new epoll item in instance %d", epoll_fd);
            goto ctl_fail;
        }

        epoll_item_reset(item);
        item->in_use = 1;
        item->fd = fd;
        item->events = event->events;
        item->data = event->data;
        item->sock = sock;
        item->epoll = epoll;
        if (epoll_item_insert_locked(epoll, item) < 0)
        {
            epoll_item_reset(item);
            dbug_error(DBG_MOD_TCP, "failed to insert epoll item for fd %d into interest tree of instance %d", fd, epoll_fd);
            goto ctl_fail;
        }

        nlist_insert_last(&sock->epoll_list, &item->sock_node);
        item->on_sock_list = 1;
        ++epoll->count;
        should_notify = epoll_item_sync_locked(item);
        break;
    case EPOLL_CTL_MOD:
        if (event == NULL)
        {
            dbug_error(DBG_MOD_TCP, "event cannot be NULL for EPOLL_CTL_MOD");
            goto ctl_fail;
        }
        if (item == NULL)
        {
            dbug_error(DBG_MOD_TCP, "fd %d is not registered in epoll instance %d", fd, epoll_fd);
            goto ctl_fail;
        }

        epoll_ready_remove_locked(epoll, item);
        item->events = event->events;
        item->data = event->data;
        item->last_ready = 0;
        should_notify = epoll_item_sync_locked(item);
        break;
    case EPOLL_CTL_DEL:
        if (item == NULL)
        {
            dbug_error(DBG_MOD_TCP, "fd %d is not registered in epoll instance %d", fd, epoll_fd);
            goto ctl_fail;
        }

        epoll_item_remove_locked(epoll, item, true);
        break;
    default:
        dbug_error(DBG_MOD_TCP, "unsupported epoll_ctl operation: %d", op);
        goto ctl_fail;
    }

    sys_mutex_unlock(epoll->locker);
    sys_mutex_unlock(epoll_sock_lock);

    if (should_notify)
    {
        epoll_notify_waiters(epoll);
    }
    return 0;

ctl_fail:
    sys_mutex_unlock(epoll->locker);
    sys_mutex_unlock(epoll_sock_lock);
    return -1;
}

int x_epoll_wait(const int epoll_fd, x_epoll_event_t* events, const int max_events, const int timeout)
{
    x_epoll_t* epoll = epoll_get(epoll_fd);
    if (epoll == NULL)
    {
        return -1;
    }
    if (events == NULL || max_events <= 0 || timeout < -1)
    {
        dbug_error(DBG_MOD_TCP, "invalid arguments for epoll_wait: events=%p, max_events=%d, timeout=%d", events, max_events, timeout);
        return -1;
    }

    int wait_time = timeout;
    net_time_t start_time;
    if (timeout > 0)
    {
        sys_time_curr(&start_time);
    }

    while (1)
    {
        sys_mutex_lock(epoll->locker);
        if (epoll->closed)
        {
            sys_mutex_unlock(epoll->locker);
            dbug_error(DBG_MOD_TCP, "epoll instance %d is closed", epoll_fd);
            return -1;
        }

        const int ready_count = epoll_drain_ready_locked(epoll, events, max_events);
        sys_mutex_unlock(epoll->locker);
        if (ready_count > 0)
        {
            return ready_count;
        }
        if (timeout == 0)
        {
            return 0;
        }

        sys_mutex_lock(epoll->locker);
        ++epoll->waiters;
        sys_mutex_unlock(epoll->locker);

        const int wait_result = sys_sem_wait(epoll->wait_sem, timeout < 0 ? 0 : (uint32_t)wait_time);

        sys_mutex_lock(epoll->locker);
        if (epoll->waiters > 0)
        {
            --epoll->waiters;
        }
        const int closed = epoll->closed;
        sys_mutex_unlock(epoll->locker);

        if (closed)
        {
            dbug_error(DBG_MOD_TCP, "epoll instance %d is closed while waiting", epoll_fd);
            return -1;
        }
        if (wait_result < 0)
        {
            return 0;
        }
        if (timeout > 0)
        {
            wait_time -= sys_time_goes(&start_time);
            if (wait_time <= 0)
            {
                return 0;
            }
        }
    }
}

int x_epoll_close(const int epoll_fd)
{
    x_epoll_t* epoll = epoll_get(epoll_fd);
    if (epoll == NULL)
    {
        return -1;
    }

    sys_mutex_lock(epoll_sock_lock);
    sys_mutex_lock(epoll->locker);

    epoll->closed = 1;
    for (int i = 0; i < EPOLL_MAX_FDS; ++i)
    {
        if (epoll->items[i].in_use)
        {
            epoll_item_remove_locked(epoll, &epoll->items[i], true);
        }
    }
    rb_tree_init(&epoll->interest_tree);
    nlist_init(&epoll->ready_list);

    sys_mutex_unlock(epoll->locker);
    sys_mutex_unlock(epoll_sock_lock);

    epoll_notify_waiters(epoll);
    sock_fd_release(epoll_fd);

    sys_mutex_lock(epoll->locker);
    epoll->fd = -1;
    epoll->in_use = 0;
    epoll->closed = 0;
    epoll->waiters = 0;
    epoll->count = 0;
    sys_mutex_unlock(epoll->locker);
    return 0;
}

void x_epoll_sock_wakeup(const sock_t* sock)
{
    if (sock == NULL || epoll_sock_lock == SYS_MUTEX_INVALID)
    {
        return;
    }

    sys_mutex_lock(epoll_sock_lock);
    nlist_node_t* node = nlist_first(&sock->epoll_list);
    while (node)
    {
        nlist_node_t* next = nlist_node_next(node);
        x_epoll_item_t* item = nlist_entry(node, x_epoll_item_t, sock_node);
        x_epoll_t* epoll = item->epoll;
        int should_notify = 0;

        if (epoll && epoll->in_use)
        {
            sys_mutex_lock(epoll->locker);
            should_notify = epoll_item_sync_locked(item);
            sys_mutex_unlock(epoll->locker);
        }

        if (should_notify)
        {
            epoll_notify_waiters(epoll);
        }
        node = next;
    }
    sys_mutex_unlock(epoll_sock_lock);
}

void x_epoll_sock_close(const sock_t* sock, const int fd)
{
    if (sock == NULL || epoll_sock_lock == SYS_MUTEX_INVALID)
    {
        return;
    }

    sys_mutex_lock(epoll_sock_lock);
    nlist_node_t* node = nlist_first(&sock->epoll_list);
    while (node)
    {
        nlist_node_t* next = nlist_node_next(node);
        x_epoll_item_t* item = nlist_entry(node, x_epoll_item_t, sock_node);
        x_epoll_t* epoll = item->epoll;
        int should_notify = 0;

        if (item->fd == fd && epoll && epoll->in_use)
        {
            sys_mutex_lock(epoll->locker);
            should_notify = item->queued;
            epoll_item_remove_locked(epoll, item, true);
            sys_mutex_unlock(epoll->locker);
        }

        if (should_notify)
        {
            epoll_notify_waiters(epoll);
        }
        node = next;
    }
    sys_mutex_unlock(epoll_sock_lock);
}

void x_epoll_fd_recheck(const int fd)
{
    sock_t* sock = sock_fd_get_socket(fd);
    if (sock)
    {
        x_epoll_sock_wakeup(sock);
    }
}

uint32_t x_epoll_poll_events(const int fd)
{
    x_epoll_t* epoll = sock_fd_get_epoll(fd);
    if (epoll == NULL)
    {
        return 0;
    }

    sys_mutex_lock(epoll->locker);
    const int ready = !nlist_is_empty(&epoll->ready_list);
    sys_mutex_unlock(epoll->locker);
    return ready ? X_POLLIN : 0;
}
