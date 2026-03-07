/**
 * TCP Mock Test - 构造假数据包测试 TCP 状态机
 *
 * 最小初始化，不依赖网卡/路由/pcap，适合单步调试。
 * 输出函数(send_ack/transmit)会因无路由失败，但不影响状态机逻辑验证。
 */

#include <stdio.h>
#include <string.h>
#include "tcp.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_state.h"
#include "tcp_buf.h"
#include "tool.h"
#include "dbug_module.h"
#include "timer.h"
#include "netif.h"
#include "ipv4.h"

/* ============================== 测试框架 ============================== */

static int pass_count = 0;
static int fail_count = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL [line %d]: %s\n", __LINE__, msg); \
        fail_count++; \
    } else { \
        printf("  PASS: %s\n", msg); \
        pass_count++; \
    } \
} while (0)

#define TEST_START(name) printf("\n========== %s ==========\n", name)

/* ============================== 地址常量 ============================== */

// 本地: 192.168.1.1:80  远端: 192.168.1.100:12345
static const uint8_t LOCAL_IP_BUF[] = {192, 168, 1, 1};
static const uint8_t REMOTE_IP_BUF[] = {192, 168, 1, 100};
static const uint8_t LOCAL_MASK_BUF[] = {255, 255, 255, 0};
static const uint16_t LOCAL_PORT = 80;
static const uint16_t REMOTE_PORT = 12345;

static net_err_t test_netif_open(netif_t* netif, void* data)
{
    (void)data;
    netif->type = NETIF_TYPE_LOOPBACK;
    netif->mtu = 1500;
    return NET_ERR_OK;
}

static net_err_t test_netif_close(netif_t* netif)
{
    (void)netif;
    return NET_ERR_OK;
}

static net_err_t test_netif_linkoutput(netif_t* netif)
{
    (void)netif;
    return NET_ERR_OK;
}

static netif_open_options_t test_netif_ops = {
    .open = test_netif_open,
    .close = test_netif_close,
    .linkoutput = test_netif_linkoutput,
};

/* ============================== 辅助函数 ============================== */

/**
 * 构造 TCP 数据包（网络字节序），checksum=0 跳过校验
 */
static pktbuf_t* build_tcp_packet(
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack,
    int f_syn, int f_ack, int f_fin, int f_rst,
    const uint8_t* data, int data_len)
{
    int total = (int)sizeof(tcp_header_t) + data_len;
    pktbuf_t* buf = pktbuf_alloc(total);
    if (buf == NULL)
    {
        printf("  ERROR: pktbuf_alloc failed\n");
        return NULL;
    }

    tcp_header_t* hdr = (tcp_header_t*)pktbuf_data(buf);
    memset(hdr, 0, sizeof(tcp_header_t));
    hdr->src_port = x_htons(src_port);
    hdr->dest_port = x_htons(dst_port);
    hdr->seq_num = x_htonl(seq);
    hdr->ack_num = x_htonl(ack);
    hdr->f_data_offset = sizeof(tcp_header_t) / 4; // 5 (20 bytes)
    hdr->f_syn = f_syn;
    hdr->f_ack = f_ack;
    hdr->f_fin = f_fin;
    hdr->f_rst = f_rst;
    hdr->window_size = x_htons(65535);
    hdr->checksum = 0;

    if (data && data_len > 0)
    {
        memcpy((uint8_t*)hdr + sizeof(tcp_header_t), data, data_len);
    }
    return buf;
}

/**
 * 创建一个 TCP socket 并设置地址，状态为 CLOSE
 */
static tcp_t* create_test_tcp(void)
{
    sock_t* sock = tcp_create(AF_INET, IPPROTO_TCP);
    if (sock == NULL)
    {
        printf("  ERROR: tcp_create failed\n");
        return NULL;
    }
    tcp_t* tcp = (tcp_t*)sock;

    ipaddr_from_buf(&sock->local_ip, LOCAL_IP_BUF);
    sock->local_port = LOCAL_PORT;
    ipaddr_from_buf(&sock->remote_ip, REMOTE_IP_BUF);
    sock->remote_port = REMOTE_PORT;

    return tcp;
}

static netif_t* create_output_capture_netif(void)
{
    netif_t* netif = netif_open("test0", &test_netif_ops, NULL);
    if (netif == NULL)
    {
        printf("  ERROR: netif_open failed\n");
        return NULL;
    }

    ipaddr_t ipaddr;
    ipaddr_t netmask;
    ipaddr_from_buf(&ipaddr, LOCAL_IP_BUF);
    ipaddr_from_buf(&netmask, LOCAL_MASK_BUF);

    if (netif_set_addr(netif, &ipaddr, &netmask, NULL) != NET_ERR_OK)
    {
        printf("  ERROR: netif_set_addr failed\n");
        netif_close(netif);
        return NULL;
    }

    if (netif_set_active(netif) != NET_ERR_OK)
    {
        printf("  ERROR: netif_set_active failed\n");
        netif_close(netif);
        return NULL;
    }

    return netif;
}

static void destroy_output_capture_netif(netif_t* netif)
{
    if (netif == NULL)
    {
        return;
    }
    netif_set_inactive(netif);
    netif_close(netif);
}

/**
 * 将 TCP 设为 ESTABLISHED 状态（模拟三次握手完成后）
 */
static void setup_established(tcp_t* tcp, uint32_t local_isn, uint32_t remote_isn)
{
    tcp_set_state(tcp, TCP_STATE_ESTABLISHED);
    tcp->send.isn = local_isn;
    tcp->send.un_ack_seq = local_isn + 1; // SYN 已被确认
    tcp->send.next_seq = local_isn + 1;
    tcp->recv.isn = remote_isn;
    tcp->recv.next_seq = remote_isn + 1;
    tcp->flags.syn_out = 0;
    tcp->flags.fin_out = 0;
    tcp->flags.irs_valid = 1;
}

/**
 * 将包喂给 tcp_input（包会被 tcp_input 释放）
 */
static net_err_t feed_packet(pktbuf_t* pkt)
{
    ipaddr_t src_ip, dst_ip;
    ipaddr_from_buf(&src_ip, REMOTE_IP_BUF);
    ipaddr_from_buf(&dst_ip, LOCAL_IP_BUF);
    return tcp_input(pkt, &src_ip, &dst_ip);
}

/* ============================== 测试用例 ============================== */

/**
 * 测试1: 三次握手（客户端视角）
 * SYN_SENT --收到 SYN+ACK--> ESTABLISHED
 */
static void test_handshake(void)
{
    TEST_START("test_handshake: 三次握手");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;

    // 模拟已发送 SYN: ISN=1000, next_seq=1001 (SYN 占一个序列号)
    tcp_set_state(tcp, TCP_STATE_SYN_SENT);
    tcp->send.isn = 1000;
    tcp->send.un_ack_seq = 1000;
    tcp->send.next_seq = 1001;
    tcp->flags.syn_out = 1;

    // 构造服务端的 SYN+ACK: seq=2000, ack=1001
    pktbuf_t* syn_ack = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2000, 1001,
        1, 1, 0, 0, // SYN+ACK
        NULL, 0);

    feed_packet(syn_ack);

    // 验证
    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED,
                "state -> ESTABLISHED");
    TEST_ASSERT(tcp->recv.isn == 2000,
                "recv.isn == 2000");
    TEST_ASSERT(tcp->recv.next_seq == 2001,
                "recv.next_seq == 2001 (SYN+1)");
    TEST_ASSERT(tcp->flags.irs_valid == 1,
                "irs_valid 已设置");
    TEST_ASSERT(tcp->flags.syn_out == 0,
                "syn_out 已清除 (SYN 被确认)");
    TEST_ASSERT(tcp->send.un_ack_seq == 1001,
                "send.un_ack_seq == 1001 (SYN 已确认)");

    tcp_free(tcp);
}

/**
 * 测试2: 数据接收
 * ESTABLISHED 收到 ACK+数据 → 数据进入 recv buffer
 *
 * 已知 BUG: tcp_data_in 不更新 recv.next_seq, 不发 ACK, 不唤醒
 */
static void test_data_recv(void)
{
    TEST_START("test_data_recv: 数据接收");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    const char* payload = "Hello";
    int payload_len = 5;

    // 服务端发送数据: seq=2001, ack=1001, 携带 "Hello"
    pktbuf_t* data_pkt = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2001, 1001,
        0, 1, 0, 0, // ACK
        (const uint8_t*)payload, payload_len);

    feed_packet(data_pkt);

    // 验证: 数据已写入 recv buffer
    TEST_ASSERT(tcp_buf_count(&tcp->recv.buf) == payload_len,
                "recv buffer 应有 5 字节数据");

    // 读出数据验证内容
    uint8_t read_buf[32] = {0};
    int n = tcp_buf_read_recv(&tcp->recv.buf, read_buf, sizeof(read_buf));
    TEST_ASSERT(n == payload_len, "读出 5 字节");
    TEST_ASSERT(memcmp(read_buf, "Hello", 5) == 0,
                "数据内容 == \"Hello\"");

    // BUG 检查: recv.next_seq 应该前进 5
    printf("  [INFO] recv.next_seq = %u (期望 2006)\n", tcp->recv.next_seq);
    TEST_ASSERT(tcp->recv.next_seq == 2006,
                "recv.next_seq == 2006 (BUG: tcp_data_in 未更新)");

    tcp_free(tcp);
}

/**
 * 测试3: 数据发送（写入 send buffer）
 */
static void test_data_send(void)
{
    TEST_START("test_data_send: 数据写入发送缓冲区");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    const char* data = "World!";
    int data_len = 6;

    int written = tcp_write_send_buf(tcp, (const uint8_t*)data, data_len);

    TEST_ASSERT(written == data_len, "写入 6 字节");
    TEST_ASSERT(tcp_buf_count(&tcp->send.buf) == data_len,
                "send buffer count == 6");

    // 写满测试
    uint8_t big_buf[TCP_SEND_BUF_SIZE];
    memset(big_buf, 'A', sizeof(big_buf));
    int remaining = tcp_buf_available(&tcp->send.buf);
    int written2 = tcp_write_send_buf(tcp, big_buf, sizeof(big_buf));
    TEST_ASSERT(written2 == remaining,
                "写满: 实际写入 == 可用空间");
    TEST_ASSERT(tcp_buf_available(&tcp->send.buf) == 0,
                "缓冲区已满");

    tcp_free(tcp);
}

/**
 * 测试4: ACK 处理（确认已发送数据）
 */
static void test_ack_process(void)
{
    TEST_START("test_ack_process: ACK 确认数据");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    // 向 send buffer 写入 10 字节数据
    const char* data = "0123456789";
    tcp_write_send_buf(tcp, (const uint8_t*)data, 10);

    // 模拟已发送: next_seq 前进 10
    tcp->send.next_seq = 1001 + 10; // 1011

    printf("  [INFO] before ACK: un_ack_seq=%u, next_seq=%u, buf_count=%d\n",
           tcp->send.un_ack_seq, tcp->send.next_seq,
           tcp_buf_count(&tcp->send.buf));

    // 服务端确认前 5 字节: ack=1006
    pktbuf_t* ack_pkt = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2001, 1006,
        0, 1, 0, 0, // ACK
        NULL, 0);

    feed_packet(ack_pkt);

    printf("  [INFO] after ACK:  un_ack_seq=%u, buf_count=%d\n",
           tcp->send.un_ack_seq, tcp_buf_count(&tcp->send.buf));

    TEST_ASSERT(tcp->send.un_ack_seq == 1006,
                "un_ack_seq == 1006 (确认了 5 字节)");
    TEST_ASSERT(tcp_buf_count(&tcp->send.buf) == 5,
                "send buffer 剩余 5 字节");

    // 再确认剩余 5 字节: ack=1011
    pktbuf_t* ack_pkt2 = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2001, 1011,
        0, 1, 0, 0,
        NULL, 0);

    feed_packet(ack_pkt2);

    TEST_ASSERT(tcp->send.un_ack_seq == 1011,
                "un_ack_seq == 1011 (全部确认)");
    TEST_ASSERT(tcp_buf_count(&tcp->send.buf) == 0,
                "send buffer 清空");

    tcp_free(tcp);
}

/**
 * 测试5: 被动关闭（收到 FIN）
 * ESTABLISHED --收到 FIN+ACK--> CLOSE_WAIT
 */
static void test_passive_close(void)
{
    TEST_START("test_passive_close: 被动关闭");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    uint32_t old_next_seq = tcp->recv.next_seq; // 2001

    // 服务端发送 FIN+ACK: seq=2001, ack=1001
    pktbuf_t* fin_pkt = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2001, 1001,
        0, 1, 1, 0, // FIN+ACK
        NULL, 0);

    feed_packet(fin_pkt);

    TEST_ASSERT(tcp->state == TCP_STATE_CLOSE_WAIT,
                "state -> CLOSE_WAIT");
    TEST_ASSERT(tcp->recv.next_seq == old_next_seq + 1,
                "recv.next_seq +1 (FIN 占一个序列号)");

    tcp_free(tcp);
}

/**
 * 测试6: RST 处理
 * ESTABLISHED --收到 RST--> CLOSE
 */
static void test_rst(void)
{
    TEST_START("test_rst: RST 重置连接");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    // 服务端发送 RST: seq=2001
    pktbuf_t* rst_pkt = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2001, 0,
        0, 0, 0, 1, // RST
        NULL, 0);

    feed_packet(rst_pkt);

    TEST_ASSERT(tcp->state == TCP_STATE_CLOSE,
                "state -> CLOSE (连接被重置)");

    tcp_free(tcp);
}

/**
 * 测试7: 环形缓冲区回绕
 * 直接测试 tcp_buf，验证块拷贝优化后的正确性
 */
static void test_tcp_buf(void)
{
    TEST_START("test_tcp_buf: 环形缓冲区回绕");

    // 使用小缓冲区 (16字节) 方便触发回绕
    uint8_t backing[16];
    tcp_buf_t buf;
    tcp_buf_init(&buf, backing, sizeof(backing));

    TEST_ASSERT(tcp_buf_available(&buf) == 16, "初始可用 16");
    TEST_ASSERT(tcp_buf_count(&buf) == 0, "初始 count 0");

    // 写入 12 字节: "ABCDEFGHIJKL"，in 到 12
    uint8_t write_data[12];
    for (int i = 0; i < 12; i++) write_data[i] = 'A' + i;
    tcp_buf_write_send(&buf, write_data, 12);

    TEST_ASSERT(tcp_buf_count(&buf) == 12, "写入后 count == 12");
    TEST_ASSERT(buf.in == 12, "in == 12");

    // 读出 8 字节，out 到 8
    uint8_t read_data[16] = {0};
    int n = tcp_buf_read_recv(&buf, read_data, 8);
    TEST_ASSERT(n == 8, "读出 8 字节");
    TEST_ASSERT(memcmp(read_data, "ABCDEFGH", 8) == 0, "内容 ABCDEFGH");
    TEST_ASSERT(buf.out == 8, "out == 8");
    TEST_ASSERT(tcp_buf_count(&buf) == 4, "剩余 4 字节");

    // 再写入 10 字节 "0123456789"
    // in=12, 写4到末尾(12..15), 再回绕写6到开头(0..5), in=6
    uint8_t write_data2[10] = "0123456789";
    tcp_buf_write_send(&buf, write_data2, 10);

    TEST_ASSERT(tcp_buf_count(&buf) == 14, "count == 14");
    TEST_ASSERT(buf.in == 6, "in == 6 (回绕)");

    // 读出全部 14 字节
    uint8_t read_data2[16] = {0};
    n = tcp_buf_read_recv(&buf, read_data2, 14);
    TEST_ASSERT(n == 14, "读出 14 字节");

    // 前4字节是之前剩余的 "IJKL"，后10字节是 "0123456789"
    TEST_ASSERT(memcmp(read_data2, "IJKL0123456789", 14) == 0,
                "回绕数据完整: IJKL0123456789");
    TEST_ASSERT(tcp_buf_count(&buf) == 0, "全部读完 count == 0");

    printf("  [INFO] 块拷贝优化验证通过\n");
}

/**
 * 测试8: keepalive 启用/禁用和状态初始化
 */
static void test_keepalive_enable(void)
{
    TEST_START("test_keepalive_enable: keepalive 启用/禁用");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    // 初始状态: keepalive 未启用
    TEST_ASSERT(tcp->flags.keep_alive == 0, "初始 keepalive 未启用");
    TEST_ASSERT(tcp->conn.keep_idle == TCP_KEEP_IDLE, "keep_idle 默认值正确");
    TEST_ASSERT(tcp->conn.keep_interval == TCP_KEEP_INTERVAL, "keep_interval 默认值正确");
    TEST_ASSERT(tcp->conn.keep_count == TCP_KEEP_COUNT, "keep_count 默认值正确");

    // 启用 keepalive
    tcp_keep_alive_start(tcp, true);
    TEST_ASSERT(tcp->flags.keep_alive == 1, "启用后 keep_alive == 1");

    // 重复启用不应崩溃
    tcp_keep_alive_start(tcp, true);
    TEST_ASSERT(tcp->flags.keep_alive == 1, "重复启用保持 keep_alive == 1");

    // 禁用 keepalive
    tcp_keep_alive_start(tcp, false);
    TEST_ASSERT(tcp->flags.keep_alive == 0, "禁用后 keep_alive == 0");

    // 重复禁用不应崩溃
    tcp_keep_alive_start(tcp, false);
    TEST_ASSERT(tcp->flags.keep_alive == 0, "重复禁用保持 keep_alive == 0");

    tcp_free(tcp);
}

/**
 * 测试9: keepalive reset 逻辑
 * 收到数据后应重置 keep_retry 并重启 idle 定时器
 */
static void test_keepalive_reset(void)
{
    TEST_START("test_keepalive_reset: keepalive 重置");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    // 启用 keepalive
    tcp_keep_alive_start(tcp, true);

    // 模拟已经重试了几次
    tcp->conn.keep_retry = 3;

    // 收到数据包时调用 reset
    tcp_keep_alive_reset(tcp);

    TEST_ASSERT(tcp->conn.keep_retry == 0, "reset 后 keep_retry == 0");
    TEST_ASSERT(tcp->flags.keep_alive == 1, "reset 后仍然启用");

    // 未启用时 reset 不应崩溃
    tcp_keep_alive_start(tcp, false);
    tcp->conn.keep_retry = 5;
    tcp_keep_alive_reset(tcp);
    TEST_ASSERT(tcp->conn.keep_retry == 5, "未启用时 reset 不修改 keep_retry");

    tcp_free(tcp);
}

/**
 * 测试10: keepalive 超时 - 探测阶段
 * 模拟 idle 定时器到期，验证 keep_retry 递增
 */
static void test_keepalive_timeout_probe(void)
{
    TEST_START("test_keepalive_timeout_probe: keepalive 超时探测");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    tcp_keep_alive_start(tcp, true);

    // 手动触发 idle 定时器到期
    // 定时器系统使用差分链表，直接调用 net_timer_check_mo 推进时间
    // keep_idle 默认 7200 秒 = 7200000 毫秒
    uint32_t idle_ms = (uint32_t)tcp->conn.keep_idle * 1000;
    net_timer_check_mo(idle_ms);

    // 第一次超时后: keep_retry 应该递增，连接不应断开
    TEST_ASSERT(tcp->conn.keep_retry == 1, "第一次超时后 keep_retry == 1");
    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED, "第一次超时后仍 ESTABLISHED");

    // 继续触发 interval 定时器到期
    uint32_t interval_ms = (uint32_t)tcp->conn.keep_interval * 1000;
    net_timer_check_mo(interval_ms);
    TEST_ASSERT(tcp->conn.keep_retry == 2, "第二次超时后 keep_retry == 2");
    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED, "第二次超时后仍 ESTABLISHED");

    tcp_kill_all_timer(tcp);
    tcp_free(tcp);
}

/**
 * 测试11: keepalive 超时 - 超过最大重试次数导致连接中止
 */
static void test_keepalive_timeout_abort(void)
{
    TEST_START("test_keepalive_timeout_abort: keepalive 超限中止");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    tcp_keep_alive_start(tcp, true);

    // 快进到 idle 超时
    uint32_t idle_ms = (uint32_t)tcp->conn.keep_idle * 1000;
    net_timer_check_mo(idle_ms);

    // 快进 keep_count - 1 次 interval 超时（第1次已在idle超时中触发）
    uint32_t interval_ms = (uint32_t)tcp->conn.keep_interval * 1000;
    for (int i = 1; i < tcp->conn.keep_count; i++)
    {
        net_timer_check_mo(interval_ms);
    }

    // keep_count 次超时后应该中止连接
    // keep_retry 从 0 开始 pre-increment, 所以 keep_count 次后 keep_retry == keep_count
    TEST_ASSERT(tcp->state == TCP_STATE_CLOSE, "超过重试次数后 state -> CLOSE");

    tcp_free(tcp);
}

/**
 * 测试12: keepalive reset 中断超时序列
 * 在探测过程中收到数据，应重置计数器回到 idle 等待
 */
static void test_keepalive_reset_interrupts_probe(void)
{
    TEST_START("test_keepalive_reset_interrupts: 数据中断探测");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    tcp_keep_alive_start(tcp, true);

    // 快进到 idle 超时，触发第一次探测
    uint32_t idle_ms = (uint32_t)tcp->conn.keep_idle * 1000;
    net_timer_check_mo(idle_ms);
    TEST_ASSERT(tcp->conn.keep_retry == 1, "第一次探测后 keep_retry == 1");

    // 再触发一次 interval 超时
    uint32_t interval_ms = (uint32_t)tcp->conn.keep_interval * 1000;
    net_timer_check_mo(interval_ms);
    TEST_ASSERT(tcp->conn.keep_retry == 2, "第二次探测后 keep_retry == 2");

    // 模拟收到数据，重置 keepalive
    tcp_keep_alive_reset(tcp);
    TEST_ASSERT(tcp->conn.keep_retry == 0, "reset 后 keep_retry == 0");
    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED, "reset 后仍 ESTABLISHED");

    // 再次快进 idle 超时，应该重新开始探测序列
    net_timer_check_mo(idle_ms);
    TEST_ASSERT(tcp->conn.keep_retry == 1, "重新开始探测 keep_retry == 1");
    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED, "仍然 ESTABLISHED");

    tcp_kill_all_timer(tcp);
    tcp_free(tcp);
}

/**
 * 测试13: 收到对端 keepalive 探测时应回 ACK
 */
static void test_keepalive_probe_ack(void)
{
    TEST_START("test_keepalive_probe_ack: keepalive 探测回 ACK");

    netif_t* netif = create_output_capture_netif();
    TEST_ASSERT(netif != NULL, "测试 netif 创建成功");
    if (!netif) return;

    tcp_t* tcp = create_test_tcp();
    if (!tcp)
    {
        destroy_output_capture_netif(netif);
        return;
    }
    setup_established(tcp, 1000, 2000);

    pktbuf_t* keepalive_pkt = build_tcp_packet(
        REMOTE_PORT, LOCAL_PORT,
        2000, 1001,
        0, 1, 0, 0,
        NULL, 0);

    feed_packet(keepalive_pkt);

    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED, "收到 keepalive 后仍 ESTABLISHED");
    TEST_ASSERT(tcp->recv.next_seq == 2001, "keepalive 不推进 recv.next_seq");

    pktbuf_t* ack_pkt = netif_get_out(netif, 0);
    TEST_ASSERT(ack_pkt != NULL, "收到 keepalive 后会回 ACK");
    if (ack_pkt)
    {
        if (pktbuf_set_cont(ack_pkt, (int)sizeof(ipv4_header_t) + (int)sizeof(tcp_header_t)) == NET_ERR_OK)
        {
            tcp_header_t* ack_hdr = (tcp_header_t*)((uint8_t*)pktbuf_data(ack_pkt) + sizeof(ipv4_header_t));
            TEST_ASSERT(x_ntohs(ack_hdr->src_port) == LOCAL_PORT, "ACK 源端口正确");
            TEST_ASSERT(x_ntohs(ack_hdr->dest_port) == REMOTE_PORT, "ACK 目的端口正确");
            TEST_ASSERT(x_ntohl(ack_hdr->seq_num) == 1001, "ACK seq = SND.NXT");
            TEST_ASSERT(x_ntohl(ack_hdr->ack_num) == 2001, "ACK ack = RCV.NXT");
            TEST_ASSERT(ack_hdr->f_ack == 1, "ACK 标志置位");
            TEST_ASSERT(ack_hdr->f_syn == 0 && ack_hdr->f_fin == 0 && ack_hdr->f_rst == 0, "仅回 ACK");
        }
        else
        {
            TEST_ASSERT(0, "ACK 包头连续可读");
        }
        pktbuf_free(ack_pkt);
    }

    tcp_free(tcp);
    destroy_output_capture_netif(netif);
}

/**
 * 测试14: tcp_kill_all_timer 清理
 */
static void test_kill_all_timer(void)
{
    TEST_START("test_kill_all_timer: 定时器清理");

    tcp_t* tcp = create_test_tcp();
    if (!tcp) return;
    setup_established(tcp, 1000, 2000);

    // 启用 keepalive 添加定时器
    tcp_keep_alive_start(tcp, true);

    // 清理所有定时器
    tcp_kill_all_timer(tcp);

    // 快进大量时间，不应触发任何超时回调（不崩溃即通过）
    net_timer_check_mo(100000000);
    TEST_ASSERT(tcp->state == TCP_STATE_ESTABLISHED, "清理后快进时间不影响状态");
    TEST_ASSERT(tcp->conn.keep_retry == 0, "清理后不触发超时");

    tcp_free(tcp);
}

/* ============================== 主函数 ============================== */

int main(void)
{
    // 只显示 TCP 模块的调试信息
    dbug_module_enable_only(DBG_MOD_TCP);

    // 最小初始化
    pktbuf_init();
    net_timer_init();
    netif_init();
    ipv4_init();
    tcp_init();

    printf("TCP Mock Test\n");
    printf("==============================================\n");

    // 运行全部测试
    test_handshake();
    test_data_recv();
    test_data_send();
    test_ack_process();
    test_passive_close();
    test_rst();
    test_tcp_buf();
    test_keepalive_enable();
    test_keepalive_reset();
    test_keepalive_timeout_probe();
    test_keepalive_timeout_abort();
    test_keepalive_reset_interrupts_probe();
    test_keepalive_probe_ack();
    test_kill_all_timer();

    // 汇总
    printf("\n==============================================\n");
    printf("结果: %d PASS, %d FAIL\n", pass_count, fail_count);
    printf("==============================================\n");

    return fail_count > 0 ? 1 : 0;
}
