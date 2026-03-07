#include "select.h"
#include <limits.h>
#include "dbug.h"
#include "sock.h"
#include "tool.h"

static sys_sem_t select_wait_sem = SYS_SEM_INVALID;
static sys_mutex_t select_wait_lock = SYS_MUTEX_INVALID;
static int select_waiters = 0;

net_err_t x_select_init(void)
{
    if (select_wait_lock == SYS_MUTEX_INVALID)
    {
        select_wait_lock = sys_mutex_create();
        if (select_wait_lock == SYS_MUTEX_INVALID)
        {
            return NET_ERR_MEM;
        }
    }

    if (select_wait_sem == SYS_SEM_INVALID)
    {
        select_wait_sem = sys_sem_create(0);
        if (select_wait_sem == SYS_SEM_INVALID)
        {
            sys_mutex_free(select_wait_lock);
            select_wait_lock = SYS_MUTEX_INVALID;
            return NET_ERR_MEM;
        }
    }

    return NET_ERR_OK;
}

static void select_zero_sets(x_fd_set* read_fds, x_fd_set* write_fds, x_fd_set* except_fds)
{
    FD_ZERO(read_fds);
    FD_ZERO(write_fds);
    FD_ZERO(except_fds);
}

static int select_fd_events(const int fd, uint32_t* events)
{
    if (sock_fd_poll_events(fd, events) < 0)
    {
        dbug_error(DBG_MOD_TCP, "failed to poll events for fd %d", fd);
        return -1;
    }

    return 0;
}

static int select_scan(const int n_fds, const x_fd_set* read_in, const x_fd_set* write_in, const x_fd_set* except_in,
                       x_fd_set* read_out, x_fd_set* write_out, x_fd_set* except_out)
{
    // 重置输出集合
    select_zero_sets(read_out, write_out, except_out);

    int ready_count = 0;
    for (int fd = 0; fd < n_fds; ++fd)
    {
        const int want_read = FD_ISSET(fd, read_in);
        const int want_write = FD_ISSET(fd, write_in);
        const int want_except = FD_ISSET(fd, except_in);
        if (!want_read && !want_write && !want_except)
        {
            continue;
        }

        uint32_t events = 0;
        if (select_fd_events(fd, &events) < 0)
        {
            return -1;
        }

        int fd_ready = 0;
        if (want_read && (events & (X_POLLIN | X_POLLHUP | X_POLLERR)))
        {
            FD_SET(fd, read_out);
            fd_ready = 1;
        }
        if (want_write && (events & (X_POLLOUT | X_POLLERR)))
        {
            FD_SET(fd, write_out);
            fd_ready = 1;
        }
        if (want_except && (events & X_POLLERR))
        {
            FD_SET(fd, except_out);
            fd_ready = 1;
        }

        if (fd_ready)
        {
            ready_count++;
        }
    }

    return ready_count;
}

void x_select_wakeup(void)
{
    if (select_wait_lock == SYS_MUTEX_INVALID || select_wait_sem == SYS_SEM_INVALID)
    {
        return;
    }

    sys_mutex_lock(select_wait_lock);
    const int waiters = select_waiters;
    sys_mutex_unlock(select_wait_lock);

    for (int i = 0; i < waiters; ++i)
    {
        sys_sem_notify(select_wait_sem);
    }
}

int x_select(const int n_fds, x_fd_set* read_fds, x_fd_set* write_fds, x_fd_set* except_fds, const x_timeval* timeout)
{
    if (n_fds < 0 || n_fds > NET_FD_MAX)
    {
        dbug_error(DBG_MOD_TCP, "invalid n_fds %d", n_fds);
        return -1;
    }
    if (timeout && (timeout->tv_sec < 0 || timeout->tv_usec < 0 || timeout->tv_usec >= 1000000))
    {
        dbug_error(DBG_MOD_TCP, "invalid timeout %lld.%06lld", (long long)timeout->tv_sec, (long long)timeout->tv_usec);
        return -1;
    }
    if (x_select_init() != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "failed to initialize select");
        return -1;
    }

    x_fd_set read_in;
    x_fd_set write_in;
    x_fd_set except_in;
    if (read_fds)
    {
        plat_memcpy(&read_in, read_fds, sizeof(x_fd_set));
    }
    else
    {
        FD_ZERO(&read_in);
    }
    if (write_fds)
    {
        plat_memcpy(&write_in, write_fds, sizeof(x_fd_set));
    }
    else
    {
        FD_ZERO(&write_in);
    }
    if (except_fds)
    {
        plat_memcpy(&except_in, except_fds, sizeof(x_fd_set));
    }
    else
    {
        FD_ZERO(&except_in);
    }

    const int wait_forever = (timeout == NULL);
    int wait_time = 0;
    net_time_t start_time;
    if (!wait_forever)
    {
        int64_t wait_ms = (int64_t)timeout->tv_sec * 1000 + (timeout->tv_usec + 999) / 1000;
        if (wait_ms > INT_MAX)
        {
            wait_ms = INT_MAX;
        }
        wait_time = (int)wait_ms;
        sys_time_curr(&start_time);
    }

    while (true)
    {
        const int ready = select_scan(n_fds, &read_in, &write_in, &except_in, read_fds, write_fds, except_fds);
        if (ready != 0)
        {
            return ready;
        }
        if (!wait_forever && wait_time == 0)
        {
            return 0;
        }

        sys_mutex_lock(select_wait_lock);
        select_waiters++;
        sys_mutex_unlock(select_wait_lock);

        const int recheck = select_scan(n_fds, &read_in, &write_in, &except_in, read_fds, write_fds, except_fds);
        if (recheck != 0)
        {
            sys_mutex_lock(select_wait_lock);
            select_waiters--;
            sys_mutex_unlock(select_wait_lock);
            return recheck;
        }

        const int wait_result = sys_sem_wait(select_wait_sem, wait_forever ? 0 : (uint32_t)wait_time);

        sys_mutex_lock(select_wait_lock);
        select_waiters--;
        sys_mutex_unlock(select_wait_lock);

        if (wait_result < 0)
        {
            if (!wait_forever)
            {
                select_zero_sets(read_fds, write_fds, except_fds);
                return 0;
            }
            dbug_error(DBG_MOD_TCP, "failed to wait on select semaphore");
            return -1;
        }

        if (!wait_forever)
        {
            wait_time -= sys_time_goes(&start_time);
            if (wait_time < 0)
            {
                wait_time = 0;
            }
        }
    }
}
