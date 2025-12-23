#include "mblock.h"

#include "dbug.h"

net_err_t mblock_init(mblock_t* mblock, void* mem, const size_t block_size, const size_t cnt, const nlocker_type_t type)
{
    uint8_t* buf = mem;
    nlist_init(&mblock->free_list);
    for (size_t i = 0; i < cnt; i++)
    {
        nlist_node_t* block = (nlist_node_t*)(buf + i * block_size);
        nlist_node_init(block);
        nlist_insert_last(&mblock->free_list, block);
    }
    if (nlocker_init(&mblock->lock, type) != NET_ERR_OK)
    {
        return NET_ERR_SYS;
    }
    if (type != NLOCKER_TYPE_NONE)
    {
        mblock->alloc_sem = sys_sem_create((int)cnt);
        if (mblock->alloc_sem == SYS_SEM_INVALID)
        {
            nlocker_destroy(&mblock->lock);
            return NET_ERR_SYS;
        }
    }
    mblock->start = mem;
    return NET_ERR_OK;
}

void* mblock_alloc(mblock_t* mblock, const int32_t timeout_ms)
{
    dbug_info("alloc: list head = %p", mblock->free_list.first);
    if (mblock->free_list.first) {
        // 尝试打印下一个节点，这里大概率会崩，证明是链表坏了
        dbug_info("alloc: next node = %p", mblock->free_list.first->next);
    }
    if (timeout_ms > 0 && mblock->lock.type == NLOCKER_TYPE_THREAD)
    {
        if (sys_sem_wait(mblock->alloc_sem, timeout_ms) < 0)
        {
            return NULL; // 超时或出错
        }
    }
    nlocker_lock(&mblock->lock);
    nlist_node_t* block = nlist_remove_first(&mblock->free_list);
    nlocker_unlock(&mblock->lock);
    return block;
}

int mblock_free_cnt(const mblock_t* mblock)
{
    if (mblock == NULL)
    {
        return -1;
    }
    nlocker_lock(&mblock->lock);
    const int cnt = nlist_count(&mblock->free_list);
    nlocker_unlock(&mblock->lock);
    return cnt;
}

void mblock_free(mblock_t* mblock, void* block)
{
    if (block == NULL)
    {
        return;
    }
    nlocker_lock(&mblock->lock);
    nlist_insert_last(&mblock->free_list, block);
    nlocker_unlock(&mblock->lock);
    if (mblock->lock.type == NLOCKER_TYPE_THREAD)
    {
        sys_sem_notify(mblock->alloc_sem);
    }
}

void mblock_destroy(const mblock_t* mblock)
{
    if (mblock == NULL)
    {
        return;
    }
    if (mblock->lock.type != NLOCKER_TYPE_NONE)
    {
        sys_sem_free(mblock->alloc_sem);
    }
    nlocker_destroy(&mblock->lock);
}
