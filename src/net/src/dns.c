#include "dns.h"
#include "dbug.h"
#include "mblock.h"
#include "timer.h"
#include "udp.h"
#include "net_api.h"

static dns_entry_t dns_entry_tbl[DNS_ENTRY_SIZE]; // DNS缓存表
static net_timer_t entry_update_timer;
static udp_t* dns_udp;
static uint16_t id;
static nlist_t req_list; // 请求列表
static mblock_t req_mblock; // 请求分配结构
static dns_req_t dns_req_list[DNS_REQ_SIZE];
static uint8_t working_buf[DNS_WORKING_BUF_SIZE];

static const uint8_t* domain_name_skip(const uint8_t* name, size_t size)
{
    const uint8_t* c = name;
    const uint8_t* end = name + size;
    while (c < end && *c)
    {
        // 压缩标签，2个字节；非压缩，取计数累加
        if ((*c & 0xc0) == 0xc0)
        {
            // 一个域名仅能包含一个指针，要么只有两个字节就只包含一个指针，要么只在结尾部分跟随一个指针
            // 压缩标签无需以'\0'结束
            if ((end - c) < 2)
            {
                return (const uint8_t*)0;
            }
            c += 2;
            goto skip_end;
        }

        uint8_t label_size = *c++;
        if ((size_t)(end - c) < label_size)
        {
            return (const uint8_t*)0;
        }
        c += label_size;
    }

    // 非压缩标签没有'\0'，这里针对普通标签判断，跳过'\0'
    if (c < end && *c == '\0')
    {
        c++;
    }
skip_end:
    return c <= end ? c : (const uint8_t*)0;
}

static void dns_entry_free(dns_entry_t* entry)
{
    ipaddr_set_any(&entry->ipaddr);
}

static void dns_req_remove(dns_req_t* req, const net_err_t err)
{
    // 没有服务器可以重试了，删除该请求
    nlist_remove(&req_list, &req->node);

    // 刷新请求结构
    req->err = err;
    if (err < NET_ERR_OK)
    {
        ipaddr_set_any(&req->ipaddr);
    }

    if (req->wait_sem != SYS_SEM_INVALID)
    {
        sys_sem_notify(req->wait_sem);
    }
}

static void dns_req_add(dns_req_t* req)
{
    req->query_id = ++id; // 纪录一下这个ID值以结构中
    req->err = NET_ERR_OK;
    req->retry_timeout = DNS_QUERY_RETRY_TMO;
    req->retry_cnt = DNS_QUERY_RETRY_CNT;
    ipaddr_set_any(&req->ipaddr);
    nlist_insert_last(&req_list, &req->node);
}

static void dns_entry_init(dns_entry_t* entry, const char* domain_name, const int ttl, const ipaddr_t* ipaddr)
{
    entry->ttl = ttl;
    ipaddr_copy(&entry->ipaddr, ipaddr);
    plat_strncpy(entry->domain_name, domain_name, DNS_DOMAIN_MAX_LEN - 1);
    entry->domain_name[DNS_DOMAIN_MAX_LEN - 1] = '\0';
}

static void dns_entry_insert(const char* domain_name, int ttl, ipaddr_t* ipaddr)
{
    dns_entry_t* free = NULL;
    dns_entry_t* oldest = NULL;

    // 空闲， 老的
    for (int i = 0; i < DNS_ENTRY_SIZE; i++)
    {
        dns_entry_t* entry = dns_entry_tbl + i;

        if (ipaddr_is_any(&entry->ipaddr))
        {
            free = entry;
            break;
        }

        if ((oldest == (dns_entry_t*)0) || (entry->ttl < oldest->ttl))
        {
            oldest = entry;
        }
    }

    if (free == (dns_entry_t*)0)
    {
        free = oldest;
    }

    dns_entry_init(free, domain_name, ttl, ipaddr);
}

static void dns_req_fail(dns_req_t* req, const net_err_t err)
{
    // 需要停止，或者超过最大重试次数，中止
    dns_req_remove(req, err);
}

static uint8_t* add_query_field(const char* domain_name, char* buf, const size_t size)
{
    // 检查长度大小：包含字符串有效长，开头的.和结束的'\0'
    if (size < (sizeof(dns_qfield_t) + plat_strlen(domain_name) + 2))
    {
        dbug_error(DBG_MOD_DNS, "no enough space for query: %s", domain_name);
        return NULL;
    }

    // 写入名字区域。先写入整个字符，构造成多个以.+字符串的形式
    char* name_buf = buf;
    name_buf[0] = '.';
    plat_strcpy(name_buf + 1, domain_name);

    // 然后将所有的.换成其之后的字符串长度
    char* c = name_buf;
    while (*c)
    {
        if (*c == '.')
        {
            // 统计后续字符串长度
            char* dot = c++;
            while (*c && (*c != '.'))
            {
                c++;
            }
            *dot = (char)(c - dot - 1);
        }
        else
        {
            c++;
        }
    }
    *c++ = '\0';

    dns_qfield_t* f = (dns_qfield_t*)c;
    f->class = htons(DNS_QUERY_CLASS_INET);
    f->type = htons(DNS_QUERY_TYPE_A);
    return (uint8_t*)f + sizeof(dns_qfield_t);
}

static net_err_t dns_send_query(const dns_req_t* req)
{
    // 构造DNS查询包头
    dns_header_t* dns_hdr = (dns_header_t*)working_buf;
    dns_hdr->id = htons(req->query_id);
    dns_hdr->flags.all = 0;
    dns_hdr->flags.rd = 1; // 期望递归
    dns_hdr->flags.all = htons(dns_hdr->flags.all);
    dns_hdr->qdcount = htons(1); // 每次只查一个域名
    dns_hdr->ancount = 0;
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;

    // 填充1个问题区段
    uint8_t* buf = working_buf + sizeof(dns_header_t);
    buf = add_query_field(req->domain, (char*)buf, sizeof(working_buf) - (buf - working_buf));
    if (!buf)
    {
        dbug_error(DBG_MOD_DNS, "add query question failed.");
        return NET_ERR_MEM;
    }

    // 向网络上发送查询消息
    struct x_sockaddr_in dest;
    plat_memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT_DEFAULT);
    dest.sin_addr.s_addr = x_inet_addr(DNS_SERVER_IP_DEFAULT);

    ssize_t res;
    return udp_sendto((sock_t*)dns_udp, working_buf, buf - working_buf, 0,
                      (const struct x_sockaddr*)&dest, sizeof(dest), &res);
}

static void dns_update_timeout(net_timer_t* timer, void* arg)
{
    // 增加age计数
    for (int i = 0; i < DNS_ENTRY_SIZE; i++)
    {
        dns_entry_t* entry = dns_entry_tbl + i;
        if (ipaddr_is_any(&entry->ipaddr))
        {
            continue;
        }
        if (!entry->ttl || (--entry->ttl == 0))
        {
            dns_entry_free(entry);
        }
    }

    // 遍历列表，进行查询超时的处理或者重传超时
    nlist_node_t* next;
    for (nlist_node_t* curr = nlist_first(&req_list); curr; curr = next)
    {
        next = nlist_node_next(curr);

        dns_req_t* req = nlist_entry(curr, dns_req_t, node);
        if (--req->retry_timeout == 0)
        {
            if (--req->retry_cnt == 0)
            {
                dns_req_fail(req, NET_ERR_TIMEOUT);
            }
            else
            {
                req->retry_timeout = DNS_QUERY_RETRY_TMO;
                dns_send_query(req);
            }
        }
    }
}


void dns_init()
{
    dbug_info(DBG_MOD_DNS, "DNS init");

    plat_memset(dns_entry_tbl, 0, sizeof(dns_entry_tbl));

    // 表刷新定时器处理
    net_timer_add(&entry_update_timer, "dns timer", dns_update_timeout, NULL, DNS_UPDATE_PERIOID * 1000,
                  TIMER_FLAG_PERIODIC);

    // 套接字初始化
    dns_udp = (udp_t*)udp_create(AF_INET, IPPROTO_UDP);

    // 建立请求表
    nlist_init(&req_list);
    mblock_init(&req_mblock, dns_req_list, sizeof(dns_req_t), DNS_REQ_SIZE, NLOCKER_TYPE_THREAD);
}

void dns_in()
{
    struct x_sockaddr_in src;
    plat_memset(&src, 0, sizeof(src));
    x_socklen_t addr_len = sizeof(src);
    ssize_t recv_len;
    net_err_t err = udp_recvfrom((sock_t*)dns_udp, working_buf, sizeof(working_buf), 0,
                                 (const struct x_sockaddr*)&src, &addr_len, &recv_len);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_DNS, "dns_in: udp_recvfrom failed, err=%d", err);
        return;
    }

    const uint8_t* rcv_end = working_buf + recv_len;

    dns_header_t* header = (dns_header_t*)working_buf;
    if (recv_len < sizeof(dns_header_t) || (header->flags.all & htons(0x8000)) == 0)
    {
        dbug_warn(DBG_MOD_DNS, "dns_in: invalid dns response");
        return;
    }
    header->id = x_ntohs(header->id);
    header->flags.all = x_ntohs(header->flags.all);
    header->qdcount = x_ntohs(header->qdcount);
    header->ancount = x_ntohs(header->ancount);
    header->nscount = x_ntohs(header->nscount);
    header->arcount = x_ntohs(header->arcount);
    dbug_info(DBG_MOD_DNS,
              "dns_in: recv dns response, id=%d, flags=0x%04x, qdcount=%d, ancount=%d, nscount=%d, arcount=%d",
              header->id, header->flags.all, header->qdcount, header->ancount, header->nscount, header->arcount);

    nlist_node_t* curr;
    nlist_for_each(curr, &req_list)
    {
        dns_req_t* req = nlist_entry(curr, dns_req_t, node);
        if (req->query_id != header->id)
        {
            continue;
        }
        if (header->flags.qr == 0)
        {
            dbug_warn(DBG_MOD_DNS, "not a responsed");
            goto req_failure;
        }
        // 不允许截断的消息
        if (header->flags.tc == 1)
        {
            dbug_warn(DBG_MOD_DNS, "response truncated");
            goto req_failure;
        }
        // 只处理A记录的响应
        if (header->ancount == 0)
        {
            dbug_warn(DBG_MOD_DNS, "no answer");
            goto req_failure;
        }

        const uint8_t* rcv_start = working_buf + sizeof(dns_header_t);
        for (int i = 0; i < header->qdcount; i++)
        {
            rcv_start = domain_name_skip(rcv_start, rcv_end - rcv_start);
            if (rcv_start == (const uint8_t*)0 || (size_t)(rcv_end - rcv_start) < sizeof(dns_qfield_t))
            {
                dbug_warn(DBG_MOD_DNS, "question size error");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            rcv_start += sizeof(dns_qfield_t);
        }

        for (int i = 0; i < header->ancount && rcv_start < rcv_end; i++)
        {
            // 跳过域名，不做检查
            rcv_start = domain_name_skip(rcv_start, rcv_end - rcv_start);
            if (rcv_start == (const uint8_t*)0)
            {
                dbug_warn(DBG_MOD_DNS, "size error");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }
            // 检查其余字段，首先空间要够
            if ((size_t)(rcv_end - rcv_start) < (sizeof(dns_afield_t) - sizeof(uint16_t)))
            {
                dbug_warn(DBG_MOD_DNS, "size error");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            // 进行必要的检查后取结果
            dns_afield_t* af = (dns_afield_t*)rcv_start;
            uint16_t af_type = x_ntohs(af->type);
            uint16_t af_class = x_ntohs(af->class);
            uint16_t rd_len = x_ntohs(af->rd_len);
            uint32_t ttl = x_ntohl(af->ttl);
            size_t af_total_size = sizeof(dns_afield_t) - sizeof(uint16_t) + rd_len;
            if ((size_t)(rcv_end - rcv_start) < af_total_size)
            {
                dbug_warn(DBG_MOD_DNS, "size error");
                err = NET_ERR_FORMAT;
                goto req_failure;
            }

            if (af_class == DNS_QUERY_CLASS_INET
                && af_type == DNS_QUERY_TYPE_A
                && rd_len == IPV4_ADDR_SIZE)
            {
                // 获取IP地址，同时往缓存表中插入新表项
                ipaddr_from_buf(&req->ipaddr, (uint8_t*)af->rdata);
                dns_entry_insert(req->domain, ttl, &req->ipaddr);

                char ip_buf[20];
                ipaddr_to_str(&req->ipaddr, ip_buf, sizeof(ip_buf));
                dbug_info(DBG_MOD_DNS, "recv dns A type: %s %s", req->domain, ip_buf);

                // 给应用发通知，通知解析完毕，退出解析
                dns_req_remove(req, NET_ERR_OK);
                return;
            }

            rcv_start += af_total_size;
        }
    req_failure:
        dns_req_fail(req, err);
        return;
    }
}

dns_req_t* dns_alloc_req()
{
    dns_req_t* req = malloc(sizeof(dns_req_t));
    if (req)
    {
        plat_memset(req, 0, sizeof(dns_req_t));
        req->wait_sem = sys_sem_create(0);
    }
    return req;
}

void dns_free_req(dns_req_t* req)
{
    if (req)
    {
        if (req->wait_sem != SYS_SEM_INVALID)
        {
            sys_sem_free(req->wait_sem);
            req->wait_sem = SYS_SEM_INVALID;
        }
        free(req);
    }
}

net_err_t dns_query_req_in(const func_msg_t* msg)
{
    dns_req_t* dns_req = msg->arg;
    size_t name_len = plat_strlen(dns_req->domain);
    if (name_len >= DNS_DOMAIN_MAX_LEN)
    {
        dbug_error(DBG_MOD_DNS, "domain name too long: %d > %d", name_len, DNS_DOMAIN_MAX_LEN);
        return NET_ERR_INVALID_PARAM;
    }

    // 是否本身就是IP地址
    ipaddr_t ipaddr;
    if (ipaddr4_form_str(&ipaddr, dns_req->domain) == NET_ERR_OK)
    {
        dns_req->ipaddr = ipaddr;
        dns_req->err = NET_ERR_OK;
        return NET_ERR_OK;
    }

    // 是否是本地地址
    if (plat_strcmp(dns_req->domain, "localhost") == 0)
    {
        ipaddr4_form_str(&dns_req->ipaddr, "127.0.0.1");
        dns_req->err = NET_ERR_OK;
        return NET_ERR_OK;
    }

    dns_req_add(dns_req);
    dns_req->err = dns_send_query(dns_req);
    if (dns_req->err != NET_ERR_OK)
    {
        nlist_remove(&req_list, &dns_req->node);
        dbug_error(DBG_MOD_DNS, "dns_query_req_in: send query failed, err=%d", dns_req->err);
        return dns_req->err;
    }

    dns_req->err = NET_ERR_OK;
    return NET_ERR_NEED_WAIT;
}

bool dns_is_arrival(const udp_t* udp)
{
    return udp == dns_udp;
}
