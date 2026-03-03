#include "exmsg.h"
#include "net_cfg.h"
#include "dbug.h"
#include "sys_plat.h"
#include "fixq.h"
#include "mblock.h"
#include "timer.h"
#include "ipv4.h"

static void* msg_tbl[EXMSG_QUEUE_SIZE];

static fixq_t msg_queue;

static exmsg_t msg_buf[EXMSG_QUEUE_SIZE];

static mblock_t msg_mblock;

net_err_t exmsg_init()
{
    dbug_info(DBG_MOD_EXMSG, "exmsg init...");

    net_err_t err = NET_ERR_OK;

    // 初始化消息内存块
    err = mblock_init(&msg_mblock, msg_buf, sizeof(exmsg_t), EXMSG_QUEUE_SIZE, NLOCKER_TYPE_THREAD);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_EXMSG, "exmsg mblock init failed, err=%d", err);
        goto fail;
    }

    // 初始化消息队列
    err = fixq_init(&msg_queue, msg_tbl, EXMSG_QUEUE_SIZE, NLOCKER_TYPE_THREAD);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_EXMSG, "exmsg queue init failed, err=%d", err);
        goto fail;
    }

    return NET_ERR_OK;

fail:
    mblock_destroy(&msg_mblock);
    fixq_destroy(&msg_queue);
    return err;
}

static net_err_t do_netif_input(const exmsg_t* msg)
{
    netif_t* netif = msg->netif.netif;
    pktbuf_t* buf;
    while ((buf = netif_get_in(netif, -1)) != NULL)
    {
        net_err_t err = NET_ERR_OK;
        // 是否注册对应链路层协议处理函数
        if (netif->link_layer != NULL)
        {
            err = netif->link_layer->input(netif, buf);
        }
        else
        {
            err = ipv4_input(netif, buf);
        }

        if (err != NET_ERR_OK)
        {
            dbug_error(DBG_MOD_EXMSG, "处理输入数据包失败，err=%d", err);
            pktbuf_free(buf);
        }
    }
    return NET_ERR_OK;
}

static net_err_t do_func(func_msg_t* func_msg)
{
    if (func_msg == NULL || func_msg->func == NULL)
    {
        return NET_ERR_INVALID_PARAM;
    }
    func_msg->err = func_msg->func(func_msg);

    sys_sem_notify(func_msg->wait_sem);
    return NET_ERR_OK;
}

static void work_thread(void* arg)
{
    dbug_info(DBG_MOD_EXMSG, "exmsg work_thread started");
    net_time_t plat_start_time;
    sys_time_curr(&plat_start_time);

    while (1)
    {
        uint32_t waitMo = net_timer_first_mo();
        // 接收消息，阻塞等待
        exmsg_t* msg = fixq_recv(&msg_queue, (int32_t)waitMo);
        if (msg != NULL)
        {
            dbug_info(DBG_MOD_EXMSG, "exmsg work_thread: received msg type=%d", msg->type);
            switch (msg->type)
            {
            case NET_EXMSG_TYPE_NETIF_IN:
                {
                    do_netif_input(msg);
                    break;
                }
            case NET_EXMSG_TYPE_FUNC:
                {
                    do_func(msg->func);
                    break;
                }
            default:
                break;
            }

            // 释放消息内存块
            mblock_free(&msg_mblock, msg);
        }
        net_timer_check_mo(sys_time_goes(&plat_start_time));
    }
}

net_err_t exmsg_start()
{
    const sys_thread_t thread = sys_thread_create(work_thread, NULL);
    if (thread == SYS_THREAD_INVALID)
    {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}

net_err_t exmsg_netif_in(netif_t* netif)
{
    exmsg_t* msg = mblock_alloc(&msg_mblock, -1);
    if (msg == NULL)
    {
        dbug_warn(DBG_MOD_EXMSG, "no free exmsg block");
        return NET_ERR_MEM;
    }
    msg->type = NET_EXMSG_TYPE_NETIF_IN;
    msg->netif.netif = netif;
    if (fixq_send(&msg_queue, msg, -1) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_EXMSG, "fixq full");
        mblock_free(&msg_mblock, msg);
        return NET_ERR_MEM;
    }
    return NET_ERR_OK;
}

net_err_t exmsg_func_exec(const exmsg_func_t func, void* arg)
{
    func_msg_t func_msg;
    func_msg.thread = sys_thread_self();
    func_msg.func = func;
    func_msg.arg = arg;
    func_msg.err = NET_ERR_OK;
    func_msg.wait_sem = sys_sem_create(0);

    if (func_msg.wait_sem == SYS_SEM_INVALID)
    {
        dbug_error(DBG_MOD_EXMSG, "create func_msg wait_sem failed");
        return NET_ERR_SYS;
    }

    exmsg_t* msg = mblock_alloc(&msg_mblock, 0);
    if (msg == NULL)
    {
        dbug_warn(DBG_MOD_EXMSG, "no free exmsg block");
        sys_sem_free(func_msg.wait_sem);
        return NET_ERR_MEM;
    }
    msg->type = NET_EXMSG_TYPE_FUNC;
    msg->func = &func_msg;
    if (fixq_send(&msg_queue, msg, 0) != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_EXMSG, "fixq full");
        mblock_free(&msg_mblock, msg);
        sys_sem_free(func_msg.wait_sem);
        return NET_ERR_MEM;
    }

    sys_sem_wait(func_msg.wait_sem, 0);
    net_err_t err = func_msg.err;
    sys_sem_free(func_msg.wait_sem);
    return err;
}
