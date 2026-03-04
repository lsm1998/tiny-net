#ifndef TINY_NET_DBUG_MODULE_H
#define TINY_NET_DBUG_MODULE_H

/**
 * 调试模块定义
 * 用于控制每个模块的日志输出
 */
typedef enum dbug_module_t
{
    // 核心模块
    DBG_MOD_PKTBUF = 0,     // 数据包缓冲区
    DBG_MOD_NETIF,          // 网络接口
    DBG_MOD_EXMSG,          // 消息模块
    DBG_MOD_TIMER,          // 定时器

    // 链路层
    DBG_MOD_ETHER,          // 以太网
    DBG_MOD_LOOP,           // 回环接口

    // 网络层
    DBG_MOD_ARP,            // ARP 协议
    DBG_MOD_IPV4,           // IPv4 协议
    DBG_MOD_ICMP,           // ICMP 协议

    // 传输层
    DBG_MOD_RAW,            // Raw Socket
    DBG_MOD_TCP,            // TCP
    DBG_MOD_UDP,            // UDP

    // Socket 层
    DBG_MOD_SOCKET,         // Socket API
    DBG_MOD_SOCK,           // Socket 核心

    // 平台层
    DBG_MOD_PLATFORM,       // 平台抽象

    // 应用层
    DBG_MOD_APP,            // 应用程序
    DBG_MOD_DNS,            // DNS 客户端

    // 其他
    DBG_MOD_COMMON,         // 通用模块

    // 模块总数
    DBG_MOD_COUNT
} dbug_module_t;

/**
 * 获取模块名称
 */
const char* dbug_module_name(dbug_module_t module);

/**
 * 启用模块日志输出
 */
void dbug_module_enable(dbug_module_t module);

/**
 * 禁用模块日志输出
 */
void dbug_module_disable(dbug_module_t module);

/**
 * 检查模块是否启用
 */
int dbug_module_is_enabled(dbug_module_t module);

/**
 * 启用所有模块
 */
void dbug_module_enable_all(void);

/**
 * 禁用所有模块
 */
void dbug_module_disable_all(void);

/**
 * 只启用指定的模块（其他全部禁用）
 */
void dbug_module_enable_only(dbug_module_t module);

/**
 * 批量设置模块
 * @param modules 模块数组
 * @param count 模块数量
 * @param enable 1=启用, 0=禁用
 */
void dbug_module_set_multiple(const dbug_module_t* modules, int count, int enable);

/**
 * 打印所有模块的状态
 */
void dbug_module_show_status(void);

#endif //TINY_NET_DBUG_MODULE_H
