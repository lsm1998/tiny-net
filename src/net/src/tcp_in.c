#include "tcp_in.h"
#include "dbug.h"
#include "tcp_out.h"
#include "tool.h"
#include "tcp_state.h"

static void tcp_seg_init(tcp_seg_t* seg, const ipaddr_t* remote_ip, const ipaddr_t* local_ip, pktbuf_t* buf)
{
    ipaddr_copy(&seg->local_ip, local_ip);
    ipaddr_copy(&seg->remote_ip, remote_ip);
    seg->header = (tcp_header_t*)pktbuf_data(buf);
    seg->buf = buf;
    seg->data_len = buf->total_size - tcp_header_size(seg->header);
    seg->seq = seg->header->seq_num;
    seg->seq_len = seg->data_len + seg->header->f_syn + seg->header->f_fin;
}

static bool tcp_seq_acceptable(const tcp_t* tcp, const tcp_seg_t* seg)
{
    int rcv_wnd = tcp_recv_window_size(tcp);
    if (seg->data_len == 0)
    {
        if (rcv_wnd == 0)
        {
            return seg->seq == tcp->recv.next_seq;
        }
        return TCP_SEQ_LE(tcp->recv.next_seq, seg->seq) &&
            TCP_SEQ_LT(seg->seq, tcp->recv.next_seq + rcv_wnd);
    }
    if (rcv_wnd == 0)
    {
        return false;
    }
    int v = TCP_SEQ_LE(tcp->recv.next_seq, seg->seq) &&
        TCP_SEQ_LT(seg->seq, tcp->recv.next_seq + rcv_wnd);
    uint32_t size_last = seg->seq + seg->seq_len - 1;
    v |= TCP_SEQ_LE(tcp->recv.next_seq, size_last) &&
        TCP_SEQ_LT(size_last, tcp->recv.next_seq + rcv_wnd);
    return v;
}

net_err_t tcp_input(pktbuf_t* buf, const ipaddr_t* src_ip, const ipaddr_t* dest_ip)
{
    static const tcp_state_proc_t proc_table[] = {
        [TCP_STATE_CLOSE] = tcp_close_in,
        [TCP_STATE_LISTEN] = tcp_listen_in,
        [TCP_STATE_SYN_SENT] = tcp_syn_sent_in,
        [TCP_STATE_SYN_RECEIVED] = tcp_syn_received_in,
        [TCP_STATE_ESTABLISHED] = tcp_established_in,
        [TCP_STATE_FIN_WAIT_1] = tcp_fin_wait_1_in,
        [TCP_STATE_FIN_WAIT_2] = tcp_fin_wait_2_in,
        [TCP_STATE_CLOSE_WAIT] = tcp_close_wait_in,
        [TCP_STATE_CLOSING] = tcp_closing_in,
        [TCP_STATE_LAST_ACK] = tcp_last_ack_in,
        [TCP_STATE_TIME_WAIT] = tcp_time_wait_in,
    };

    // tcp_header_t* header = (tcp_header_t*)pktbuf_data(buf);
    if (pktbuf_set_cont(buf, sizeof(tcp_header_t)) < 0)
    {
        dbug_error(DBG_MOD_TCP, "set cont failed.");
        return -1;
    }
    tcp_header_t* header = (tcp_header_t*)pktbuf_data(buf);
    if (header->checksum != 0)
    {
        pktbuf_reset_access(buf);
        uint16_t checksum = checksum16_pseudo(buf, src_ip, dest_ip, IPPROTO_TCP);
        if (checksum != 0)
        {
            dbug_warn(DBG_MOD_TCP, "tcp_input: invalid checksum");
            return NET_ERR_CHECKSUM;
        }
    }
    if (buf->total_size < sizeof(tcp_header_t) || tcp_header_size(header) > (int)buf->total_size)
    {
        dbug_warn(DBG_MOD_TCP, "tcp_input: packet too short");
        return NET_ERR_FRAME;
    }

    if (header->dest_port == 0 || header->src_port == 0)
    {
        dbug_warn(DBG_MOD_TCP, "tcp_input: invalid port");
        return NET_ERR_PORT_UNREACH;
    }

    if (header->flags == 0)
    {
        dbug_warn(DBG_MOD_TCP, "tcp_input: no flags set");
        return NET_ERR_PROTOCOL;
    }

    header->dest_port = x_ntohs(header->dest_port);
    header->src_port = x_ntohs(header->src_port);
    header->seq_num = x_ntohl(header->seq_num);
    header->ack_num = x_ntohl(header->ack_num);
    header->window_size = x_ntohs(header->window_size);
    header->urgent_ptr = x_ntohs(header->urgent_ptr);

    tcp_seg_t seg;
    tcp_seg_init(&seg, src_ip, dest_ip, buf);

    tcp_t* tcp = tcp_find(dest_ip, header->dest_port, src_ip, header->src_port);
    if (tcp == NULL)
    {
        dbug_warn(DBG_MOD_TCP, "tcp_input: no matching socket for dest port %d", header->dest_port);
        tcp_close_in(NULL, &seg);
        // tcp_send_reset(&seg);
        pktbuf_free(buf);
        return NET_ERR_OK;
    }

    tcp_keep_alive_reset(tcp);

    // 移动数据指针到数据部分
    net_err_t err = pktbuf_seek(buf, (int)tcp_header_size(header));
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "seek failed.");
        return NET_ERR_SIZE;
    }

    if (tcp->state != TCP_STATE_CLOSE && tcp->state != TCP_STATE_SYN_SENT &&
        tcp->state != TCP_STATE_LISTEN)
    {
        if (!tcp_seq_acceptable(tcp, &seg))
        {
            dbug_error(DBG_MOD_TCP, "tcp_input: unacceptable seq, recv_next=%u, seg_seq=%u, seg_len=%u",
                       tcp->recv.next_seq, seg.seq, seg.seq_len);
            goto seg_drop;
        }
    }

    err = proc_table[tcp->state](tcp, &seg);
    if (err != NET_ERR_OK)
    {
        dbug_error(DBG_MOD_TCP, "tcp_input: state proc failed, err=%d", err);
        return err;
    }
seg_drop:
    pktbuf_free(buf);
    return NET_ERR_OK;
}

static int copy_data_to_recv_buf(tcp_t* tcp, const tcp_seg_t* seg)
{
    // tcp_header_t* tcp_hdr = seg->header;
    pktbuf_t* buf = seg->buf;

    // data_offset 相对于缓存开始的偏移量。目前只处理==0的情况，以便过滤掉调试中收到的对方重传的数据包
    int data_offset = (int)(seg->seq - tcp->recv.next_seq); // 非0时，表示出现了空洞
    if (seg->data_len && data_offset == 0)
    {
        // 拷贝数据，目前暂不支持空洞的写入
        return tcp_buf_write_recv(&tcp->recv.buf, data_offset, buf, (int)seg->data_len);
    }
    return 0;
}

net_err_t tcp_data_in(tcp_t* tcp, tcp_seg_t* seg)
{
    // 拷贝数据到接收缓冲区
    int size = copy_data_to_recv_buf(tcp, seg);
    if (size < 0)
    {
        dbug_error(DBG_MOD_TCP, "copy data to tcp recv_buf failed.");
        return NET_ERR_SIZE;
    }

    int wakeup = 0;
    if(size > 0)
    {
         tcp->recv.next_seq += (uint32_t)size;
         wakeup++;
    }

    tcp_header_t* header = seg->header;
    if (header->f_fin && size == (int)seg->data_len)
    {
        tcp->recv.next_seq++;
        tcp->flags.fin_in = 1;
        wakeup++;
    }

    if (wakeup > 0)
    {
        tcp_send_ack(tcp, seg);
        if (tcp->flags.fin_in)
        {
            sock_wakeup(&tcp->base, SOCK_WAIT_ALL, NET_ERR_CLOSE);
        }
        else
        {
            sock_wakeup(&tcp->base, SOCK_WAIT_READ, NET_ERR_OK);
        }
    }

    return NET_ERR_OK;
}
