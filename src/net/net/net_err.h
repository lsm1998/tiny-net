#ifndef TINY_NET_NET_ERR_H
#define TINY_NET_NET_ERR_H

typedef enum net_err_t
{
    NET_ERR_NEED_WAIT = 1, // 需要等待
    NET_ERR_OK = 0, // 成功
    NET_ERR_SYS = -1, // 系统错误
    NET_ERR_MEM = -2, // 内存错误
    NET_ERR_INVALID_PARAM = -3, // 无效参数
    NET_ERR_INVALID_STATE = -4, // 无效状态
    NET_ERR_IO = -5, // 输入输出错误
    NET_ERR_FRAME = -6, // 数据包格式错误
    NET_ERR_TIMEOUT = -7, // 超时
    NET_ERR_TARGET_ADDR_MATCH = -8, // 目标地址不匹配
    NET_ERR_FULL = -9, // 资源已满
    NET_ERR_CHECKSUM = -10, // 校验和错误
    NET_ERR_EXIST = -11, // 已存在
    NET_ERR_PROTOCOL = -12, // 协议错误
    NET_ERR_OPTION = -13, // 选项错误
    NET_ERR_NO_ROUTE = -14, // 无路由
    NET_ERR_PORT_UNREACH = -15, // 端口不可达
    NET_ERR_ADDR_UNSET = -16, // 地址未设置
    NET_ERR_ADDR_IN_USE = -17, // 地址已被使用
    NET_ERR_IP_UNREACH = -18, // IP不可达
    NET_ERR_STATE = -19, // 状态错误
    NET_ERR_REST = -20, // 连接被重置
    NET_ERR_CLOSE = -21, // 连接已关闭
    NET_ERR_SIZE = -22, // 大小错误
    NET_ERR_UNIMPLEMENTED = -23, // 功能未实现
    NET_ERR_ADDR = -30, // 地址错误
    NET_ERR_FORMAT = -31, // 格式错误
    NET_ERR_RESET = -32, // 连接被重置
} net_err_t;

#endif //TINY_NET_NET_ERR_H
