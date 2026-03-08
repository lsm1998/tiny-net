#include "tcp_out.h"
#include "dbug.h"
#include "ipv4.h"
#include "tool.h"
#include "protocol.h"

static net_err_t send_out(tcp_header_t* out, pktbuf_t* buf, const ipaddr_t* remote_ip, const ipaddr_t* local_ip)
{
    out->src_port = x_htons(out->src_port);
    out->dest_port = x_htons(out->dest_port);
    out->seq_num = x_htonl(out->seq_num);
    out->ack_num = x_htonl(out->ack_num);
    out->window_size = x_htons(out->window_size);
    out->urgent_ptr = x_htons(out->urgent_ptr);
    out->checksum = 0;
    out->checksum = checksum16_pseudo(buf, local_ip, remote_ip, PROTOCOL_TYPE_TCP);

    net_err_t err = ipv4_output(PROTOCOL_TYPE_TCP, remote_ip, local_ip, buf);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "send_out: ipv4_output failed, err=%d", err);
        pktbuf_free(buf);
        return err;
    }
    return NET_ERR_OK;
}

static int copy_send_data(const tcp_t* tcp, pktbuf_t* buf, int data_offset, int data_len)
{
    if (data_len == 0)
    {
        return 0;
    }
    net_err_t err = pktbuf_resize(buf, (int)sizeof(tcp_header_t) + data_len);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "copy_send_data: pktbuf_resize failed, err=%d", err);
        return -1;
    }
    tcp_header_t* header = (tcp_header_t*)pktbuf_data(buf);
    pktbuf_reset_access(buf);
    pktbuf_seek(buf, (int)tcp_header_size(header));

    tcp_buf_read_send(&tcp->send.buf, buf, data_offset, data_len);
    return data_len;
}

static int get_unacked_data_len(const tcp_t* tcp)
{
    int unacked = (int)tcp->send.next_seq - (int)tcp->send.un_ack_seq;
    if (unacked <= 0)
    {
        return 0;
    }

    if (tcp->flags.syn_out && unacked > 0)
    {
        unacked--;
    }

    if (tcp->flags.fin_out && tcp_buf_count(&tcp->send.buf) == 0 && unacked > 0)
    {
        unacked--;
    }

    int buf_count = tcp_buf_count(&tcp->send.buf);
    if (unacked > buf_count)
    {
        unacked = buf_count;
    }
    return unacked < 0 ? 0 : unacked;
}

static int get_unsent_data_len(const tcp_t* tcp)
{
    int unsent = tcp_buf_count(&tcp->send.buf) - get_unacked_data_len(tcp);
    return unsent > 0 ? unsent : 0;
}

static bool has_new_syn(const tcp_t* tcp)
{
    return tcp->flags.syn_out && (tcp->send.next_seq == tcp->send.un_ack_seq);
}

static bool has_new_fin(const tcp_t* tcp)
{
    return tcp->flags.fin_out
           && (tcp_buf_count(&tcp->send.buf) == 0)
           && (tcp->send.next_seq == tcp->send.un_ack_seq);
}

static bool has_new_send(const tcp_t* tcp)
{
    return has_new_syn(tcp) || has_new_fin(tcp) || (get_unsent_data_len(tcp) > 0);
}

static bool has_unacked_send(const tcp_t* tcp)
{
    return TCP_SEQ_LT(tcp->send.un_ack_seq, tcp->send.next_seq);
}

static void backoff_rto(tcp_t* tcp)
{
    if (tcp->send.rto <= 0)
    {
        tcp->send.rto = TCP_INIT_RTO;
    }

    if (tcp->send.rto < TCP_MAX_RTO)
    {
        tcp->send.rto <<= 1;
        if (tcp->send.rto > TCP_MAX_RTO)
        {
            tcp->send.rto = TCP_MAX_RTO;
        }
    }
}

static void get_send_info(const tcp_t* tcp, bool retrans, int* offset, int* dlen)
{
    if (retrans)
    {
        *offset = 0;
        *dlen = get_unacked_data_len(tcp);
    }
    else
    {
        *offset = get_unacked_data_len(tcp);
        *dlen = get_unsent_data_len(tcp);
    }

    // 非零窗口, 首先不能超过MSS
    *dlen = *dlen > tcp->mss ? tcp->mss : *dlen;
}

net_err_t tcp_send_reset(const tcp_seg_t* seg)
{
    tcp_header_t* in = seg->header;

    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_header_t));
    if (buf == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_send_reset: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }

    tcp_header_t* out = (tcp_header_t*)pktbuf_data(buf);
    out->src_port = in->dest_port;
    out->dest_port = in->src_port;
    out->seq_num = 0;
    out->ack_num = seg->seq + seg->seq_len;
    out->flags = 0;
    out->f_rst = 1;
    out->window_size = 0;
    out->checksum = 0;
    out->urgent_ptr = 0;
    tcp_set_header_size(out, sizeof(tcp_header_t));

    if (in->f_ack)
    {
        out->seq_num = in->ack_num;
        out->ack_num = 0;
        out->f_ack = 0;
    }
    else
    {
        out->ack_num = seg->seq + seg->seq_len;
        out->f_ack = 1;
    }

    return send_out(out, buf, &seg->remote_ip, &seg->local_ip);
}

static void write_tcp_option(const tcp_t* tcp, pktbuf_t* buf)
{
    // 目前只支持MSS选项
    tcp_option_mss_t mss_option;
    mss_option.kind = TCP_OPTION_MSS;
    mss_option.length = sizeof(tcp_option_mss_t);
    mss_option.mss = x_htons(tcp->mss);

    int options_size = sizeof(mss_option);

    net_err_t err = pktbuf_resize(buf, (int)sizeof(tcp_header_t) + options_size);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "write_tcp_option: pktbuf_resize failed, err=%d", err);
        return;
    }
    pktbuf_seek(buf, sizeof(tcp_header_t));
    err = pktbuf_write(buf, (const uint8_t*)&mss_option, sizeof(mss_option));
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "write_tcp_option: pktbuf_write failed, err=%d", err);
        return;
    }
}

net_err_t tcp_transmit(tcp_t* tcp)
{
    int data_len, data_offset;
    get_send_info(tcp, false, &data_offset, &data_len);
    if (data_len < 0)
    {
        return NET_ERR_OK;
    }

    if (data_len == 0 && tcp->flags.syn_out == 0 && tcp->flags.fin_out == 0)
    {
        return NET_ERR_OK; // 没有数据需要发送
    }

    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_header_t));
    if (buf == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_transmit: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }
    tcp_header_t* header = (tcp_header_t*)pktbuf_data(buf);
    plat_memset(header, 0, sizeof(tcp_header_t));
    header->src_port = tcp->base.local_port;
    header->dest_port = tcp->base.remote_port;
    header->seq_num = tcp->send.next_seq;
    header->ack_num = tcp->recv.next_seq;
    header->flags = 0;
    header->f_syn = tcp->flags.syn_out;
    header->f_ack = tcp->flags.irs_valid;
    if (tcp_buf_count(&tcp->send.buf) == 0)
    {
        header->f_fin = tcp->flags.fin_out;
    }
    else
    {
        header->f_fin = 0;
    }
    header->window_size = tcp_recv_window_size(tcp);
    header->urgent_ptr = 0;

    if (header->f_syn == 1)
    {
        // 设置options
        write_tcp_option(tcp, buf);
    }

    tcp_set_header_size(header, buf->total_size);

    copy_send_data(tcp, buf, data_offset, data_len);

    tcp->send.next_seq += header->f_syn + header->f_fin + data_len;
    return send_out(header, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

net_err_t tcp_send_syn(tcp_t* tcp)
{
    tcp->flags.syn_out = 1;
    // tcp_transmit(tcp);
    tcp_out_event(tcp, TCP_OUT_EVENT_SEND);
    return NET_ERR_OK;
}

net_err_t tcp_ack_process(tcp_t* tcp, const tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;

    if (TCP_SEQ_LE(header->ack_num, tcp->send.un_ack_seq))
    {
        return NET_ERR_OK; // ACK号没有超过最后一个未确认的序列号，说明没有新的ACK确认，不需要处理
    }
    if (TCP_SEQ_LT(tcp->send.next_seq, header->ack_num))
    {
        dbug_warn(DBG_MOD_TCP, "tcp_ack_process: invalid ACK number %u, un_ack_seq=%u, next_seq=%u",
                  header->ack_num, tcp->send.un_ack_seq, tcp->send.next_seq);
        return NET_ERR_FRAME; // ACK号超过了下一个要发送的序列号，说明ACK号无效
    }

    // 如果之前发送了SYN报文，并且收到了对方的ACK报文，说明SYN报文已经被确认了，可以将未确认的序列号加1，并清除SYN标志
    if (tcp->flags.syn_out)
    {
        tcp->send.un_ack_seq++;
        tcp->flags.syn_out = 0;
    }

    int ack_count = (int)header->ack_num - (int)tcp->send.un_ack_seq;
    int un_ack_count = (int)tcp->send.next_seq - (int)tcp->send.un_ack_seq;
    int clamped_ack_count = ack_count < un_ack_count ? ack_count : un_ack_count;
    if (clamped_ack_count > 0)
    {
        sock_wakeup(&tcp->base, SOCK_WAIT_WRITE, NET_ERR_OK);
        tcp->send.un_ack_seq += clamped_ack_count;

        clamped_ack_count -= tcp_buf_remove(&tcp->send.buf, clamped_ack_count);
        if (tcp->flags.fin_out && clamped_ack_count > 0)
        {
            tcp->flags.fin_out = 0;
        }
    }
    return NET_ERR_OK;
}

net_err_t tcp_send_ack(tcp_t* tcp, tcp_seg_t* seg)
{
    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_header_t));
    if (buf == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_send_ack: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }
    tcp_header_t* header = (tcp_header_t*)pktbuf_data(buf);

    plat_memset(header, 0, sizeof(tcp_header_t));
    header->src_port = tcp->base.local_port;
    header->dest_port = tcp->base.remote_port;
    header->seq_num = tcp->send.next_seq;
    header->ack_num = tcp->recv.next_seq;
    header->flags = 0;
    tcp_set_header_size(header, sizeof(tcp_header_t));
    header->f_syn = 0;
    header->f_ack = 1;
    header->window_size = tcp_recv_window_size(tcp);
    header->urgent_ptr = 0;

    return send_out(header, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

net_err_t tcp_send_fin(tcp_t* tcp)
{
    tcp->flags.fin_out = 1;
    // tcp_transmit(tcp);
    tcp_out_event(tcp, TCP_OUT_EVENT_SEND);
    return NET_ERR_OK;
}

int tcp_write_send_buf(tcp_t* tcp, const uint8_t* buf, const size_t len)
{
    int available = tcp_buf_available(&tcp->send.buf);
    if (available <= 0)
    {
        return 0;
    }
    int write_len = len < available ? (int)len : available;
    tcp_buf_write_send(&tcp->send.buf, buf, write_len);
    return write_len;
}

net_err_t tcp_send_keep_alive(const tcp_t* tcp)
{
    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_header_t));
    if (buf == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_send_reset: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }
    tcp_header_t* out = (tcp_header_t*)pktbuf_data(buf);
    out->src_port = tcp->base.local_port;
    out->dest_port = tcp->base.remote_port;
    out->seq_num = tcp->send.next_seq - 1;
    out->ack_num = tcp->recv.next_seq;
    out->flags = 0;
    out->f_ack = 1;
    out->window_size = tcp_recv_window_size(tcp);
    out->checksum = 0;
    out->urgent_ptr = 0;
    tcp_set_header_size(out, sizeof(tcp_header_t));
    return send_out(out, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}


net_err_t tcp_send_reset_with_tcp(const tcp_t* tcp)
{
    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_header_t));
    if (buf == NULL)
    {
        dbug_error(DBG_MOD_TCP, "tcp_send_reset: pktbuf_alloc failed");
        return NET_ERR_MEM;
    }
    tcp_header_t* out = (tcp_header_t*)pktbuf_data(buf);
    out->src_port = tcp->base.local_port;
    out->dest_port = tcp->base.remote_port;
    out->seq_num = tcp->send.next_seq;
    out->ack_num = tcp->recv.next_seq;
    out->flags = 0;
    out->f_rst = 1;
    out->f_ack = 1;
    out->window_size = tcp_recv_window_size(tcp);
    out->checksum = 0;
    out->urgent_ptr = 0;
    tcp_set_header_size(out, sizeof(tcp_header_t));
    return send_out(out, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

const char* tcp_ostate_name(tcp_ostate_t ostate)
{
    switch (ostate)
    {
    case TCP_OSTATE_IDLE:
        return "IDLE";
    case TCP_OSTATE_SENDING:
        return "SENDING";
    case TCP_OSTATE_RETRANS:
        return "RETRANS";
    default:
        return "UNKNOWN";
    }
}

net_err_t tcp_retransmit(tcp_t* tcp)
{
    // 注意要考虑FIN和SYN，且不能把需要重发的算进去，只算此次新的发的数据
    int dlen, doff;
    get_send_info(tcp, true, &doff, &dlen);
    if (dlen < 0)
    {
        return NET_ERR_OK;
    }
    // 由于发送可能由应用发起，也可能是在收到ACK后发起。因此，需要检查当前是否可以发送
    // 如果没有需要可以发送的，并且当前状态不允许发送，则直接退出
    int seq_len = dlen;
    if (tcp->flags.syn_out)
    {
        seq_len++;
    }

    if (tcp->flags.fin_out)
    {
        seq_len++;
    }

    if (seq_len == 0)
    {
        return NET_ERR_OK;
    }

    // 分配一个TCP包，暂不考虑选项区域和头部区域
    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_header_t));
    if (!buf)
    {
        dbug_error(DBG_MOD_TCP, "no buffer");
        return NET_ERR_OK;
    }

    // 生成数据包头
    tcp_header_t* hdr = (tcp_header_t*)pktbuf_data(buf);
    hdr->src_port = tcp->base.local_port;
    hdr->dest_port = tcp->base.remote_port;
    hdr->seq_num = tcp->send.un_ack_seq; // 从una开始发送
    hdr->ack_num = tcp->recv.next_seq;
    hdr->flags = 0;
    hdr->f_syn = tcp->flags.syn_out; // 发送后不清理，因为可能要重传
    if (hdr->f_syn)
    {
        // syn置位，写入SYN选项, 首次连接，告诉对方自己的一些信息
        write_tcp_option(tcp, buf);
    }

    // 整个TCP传输中，除第一次传递之外，其它都需要发送ACK
    hdr->f_ack = tcp->flags.irs_valid;
    hdr->window_size = (uint16_t)tcp_recv_window_size(tcp);
    hdr->urgent_ptr = 0; // 不支持紧急数据
    tcp_set_header_size(hdr, buf->total_size);

    // 拷贝要发送的数据，从偏移量为0开始发送
    copy_send_data(tcp, buf, doff, dlen);

    // 当FIN标志位置位，且此次发送的数据为整个缓冲中所有的数据时，FIN才需要发送出去
    // 否则，应当等所有的数据都被发送完毕时，FIN才应当被发送
    if (tcp->flags.fin_out)
    {
        hdr->f_fin = (tcp_buf_count(&tcp->send.buf) == 0) ? 1 : 0;
    }

    // 计算此次重发，有多少新数据被发送，将其统计到snd.nxt中
    // 不必考虑SYN，重发时SYN肯定是之前已经发过了，不能计算在内
    // 也不必考虑FIN，因为之前的transmit，FIN肯定也是已经发过不了，所以不计算在内
    uint32_t retrans_end = tcp->send.un_ack_seq + hdr->f_syn + hdr->f_fin + dlen;
    if (TCP_SEQ_LT(tcp->send.next_seq, retrans_end))
    {
        tcp->send.next_seq = retrans_end;
    }
    dbug_info(DBG_MOD_TCP, "tcp send: seq %u, ack %u, dlen %d, seqlen: %d, %s",
              hdr->seq_num, hdr->ack_num, dlen, seq_len, tcp_ostate_name(tcp->send.ostate));
    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

static void tcp_out_timer_tmo(net_timer_t* timer, void* arg)
{
    tcp_t* tcp = arg;

    // 作为警告，方便观察
    dbug_info(DBG_MOD_TCP, "timer tmo: %s", tcp_ostate_name(tcp->send.ostate));

    // 根据状态做不同的处理
    switch (tcp->send.ostate)
    {
    case TCP_OSTATE_SENDING:
        {
            // 发送状态超时，那么此时就应该进入重传状态, 重发所有数据
            net_err_t err = tcp_retransmit(tcp);
            if (err < 0)
            {
                dbug_error(DBG_MOD_TCP, "rexmit failed.");
                return;
            }

            // 进入重发状态, 启动重传定时器。然后重传有几次渐进变化的过程
            tcp->send.retrans_count = 1;
            backoff_rto(tcp);
            tcp->send.ostate = TCP_OSTATE_RETRANS;
            net_timer_add(&tcp->send.retrans_timer, tcp_ostate_name(tcp->send.ostate), tcp_out_timer_tmo, tcp,
                          tcp->send.rto, 0);
            break;
        }
    case TCP_OSTATE_RETRANS:
        {
            if (++tcp->send.retrans_count > tcp->send.retrans_max)
            {
                dbug_error(DBG_MOD_TCP, "retrans tmo err");
                tcp_abort(tcp, NET_ERR_TIMEOUT);
                return;
            }

            // 继续重发
            net_err_t err = tcp_retransmit(tcp);
            if (err < 0)
            {
                dbug_error(DBG_MOD_TCP, "retrans failed.");
                return;
            }

            backoff_rto(tcp);
            net_timer_add(&tcp->send.retrans_timer, tcp_ostate_name(tcp->send.ostate), tcp_out_timer_tmo, tcp,
                          tcp->send.rto, 0);
            break;
        }
    default:
        dbug_error(DBG_MOD_TCP, "tcp state error: %d", tcp->state);
    }
}

static void tcp_set_ostate(tcp_t* tcp, const tcp_ostate_t state)
{
    dbug_info(DBG_MOD_TCP, "tcp_set_ostate: %s -> %s", tcp_ostate_name(tcp->send.ostate), tcp_ostate_name(state));
    tcp->send.ostate = state;

    int tmo = 0;
    switch (state)
    {
    case TCP_OSTATE_IDLE:
        tcp->send.ostate = state;
        tcp->send.retrans_count = 0;
        tcp->send.rto = TCP_INIT_RTO;
        net_timer_remove(&tcp->send.retrans_timer); // 移除定时器
        return;
    case TCP_OSTATE_SENDING:
    case TCP_OSTATE_RETRANS:
        tmo = tcp->send.rto; // 仍然使用RTO
        break;
    default:
        dbug_error(DBG_MOD_TCP, "tcp_set_ostate: invalid state %d", state);
    }
    tcp->send.ostate = state;
    // 移除定时器
    net_timer_remove(&tcp->send.retrans_timer);
    net_timer_add(&tcp->send.retrans_timer, tcp_ostate_name(tcp->send.ostate), tcp_out_timer_tmo, tcp, tmo, 0);
}

static void tcp_ostate_idle_in(tcp_t* tcp, const tcp_out_event_t event)
{
    switch (event)
    {
    case TCP_OUT_EVENT_SEND:
        if (!has_new_send(tcp))
        {
            break;
        }
        if ((tcp_transmit(tcp) == NET_ERR_OK) && has_unacked_send(tcp))
        {
            tcp_set_ostate(tcp, TCP_OSTATE_SENDING);
        }
        break;
    default:
        break;
    }
}

static void tcp_ostate_sending_in(tcp_t* tcp, const tcp_out_event_t event)
{
    switch (event)
    {
    case TCP_OUT_EVENT_SEND:
        if (tcp->send.un_ack_seq == tcp->send.next_seq || tcp->flags.fin_out)
        {
            if (has_new_send(tcp))
            {
                if ((tcp_transmit(tcp) == NET_ERR_OK) && has_unacked_send(tcp))
                {
                    tcp_set_ostate(tcp, TCP_OSTATE_SENDING);
                }
            }
            else if (!has_unacked_send(tcp)) // 没有数据要发，进入空闲状态
            {
                tcp_set_ostate(tcp, TCP_OSTATE_IDLE);
            }
        }
        break;
    default:
        break;
    }
}

static void tcp_ostate_retrans_in(tcp_t* tcp, const tcp_out_event_t event)
{
    switch (event)
    {
    case TCP_OUT_EVENT_SEND:
        {
            if (tcp->send.un_ack_seq == tcp->send.next_seq || tcp->flags.fin_out)
            {
                if (has_new_send(tcp))
                {
                    // 发送前需要检查窗口，如果为0则进入坚持状态，否则会进入普通发送状态
                    if ((tcp_transmit(tcp) == NET_ERR_OK) && has_unacked_send(tcp))
                    {
                        tcp_set_ostate(tcp, TCP_OSTATE_SENDING);
                    }
                }
                else if (!has_unacked_send(tcp))
                {
                    tcp_set_ostate(tcp, TCP_OSTATE_IDLE);
                }
            }
            else
            {
                tcp_set_ostate(tcp, TCP_OSTATE_RETRANS);
                tcp_retransmit(tcp);
            }
            break;
        }
    default:
        break;
    }
}

typedef void (*tcp_ostate_handler_t)(tcp_t* tcp, tcp_out_event_t event);

void tcp_out_event(tcp_t* tcp, const tcp_out_event_t event)
{
    static tcp_ostate_handler_t handlers[] = {
        [TCP_OSTATE_IDLE] = tcp_ostate_idle_in,
        [TCP_OSTATE_SENDING] = tcp_ostate_sending_in,
        [TCP_OSTATE_RETRANS] = tcp_ostate_retrans_in,
    };

    if (tcp->send.ostate >= TCP_OSTATE_MAX)
    {
        dbug_error(DBG_MOD_TCP, "tcp_out_event: invalid ostate %s", tcp_ostate_name(tcp->send.ostate));
        return;
    }
    handlers[tcp->send.ostate](tcp, event);
}
