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
        sys_sem_free(req->wait_sem);
        req->wait_sem = SYS_SEM_INVALID;
    }
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

    return udp_sendto((sock_t*)dns_udp, working_buf, buf - working_buf, 0,
                      (const struct x_sockaddr*)&dest, sizeof(dest), (ssize_t*)0);
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
        sys_sem_free(req->wait_sem);
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

    // 其他情况，发起DNS查询
    dns_req_t query_req;
    plat_memset(&query_req, 0, sizeof(query_req));
    plat_strncpy(query_req.domain, dns_req->domain, DNS_DOMAIN_MAX_LEN);
    query_req.domain[DNS_DOMAIN_MAX_LEN - 1] = '\0';
    query_req.query_id = ++id;
    query_req.retry_cnt = DNS_QUERY_RETRY_CNT;
    query_req.retry_timeout = DNS_QUERY_RETRY_TMO;
    query_req.wait_sem = dns_req->wait_sem;
    dns_req->err = dns_send_query(&query_req);
    if (dns_req->err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_DNS, "dns_query_req_in: send query failed, err=%d", dns_req->err);
        return dns_req->err;
    }

    dns_req->err = NET_ERR_OK;
    return NET_ERR_OK;
}
