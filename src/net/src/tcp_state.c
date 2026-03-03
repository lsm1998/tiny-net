#include "tcp_state.h"
#include "dbug.h"
#include "tcp_out.h"
#include "tcp_in.h"

const char* tcp_state_name(const tcp_state_t state)
{
    static const char* state_names[TCP_STATE_MAX] = {
        "FREE",
        "CLOSE",
        "LISTEN",
        "SYN_SENT",
        "SYN_RECEIVED",
        "ESTABLISHED",
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "CLOSE_WAIT",
        "CLOSING",
        "LAST_ACK",
        "TIME_WAIT"
    };
    return state < TCP_STATE_MAX ? state_names[state] : "UNKNOWN";
}

void tcp_set_state(tcp_t* tcp, const tcp_state_t state)
{
    dbug_info(DBG_MOD_TCP, "TCP state change: %s -> %s",
              tcp_state_name(tcp->state), tcp_state_name(state));
    tcp->state = state;
}

net_err_t tcp_close_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_rst == 0)
    {
        tcp_send_reset(seg);
    }
    return NET_ERR_OK;
}

net_err_t tcp_listen_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_rst) // 如果是RST报文，直接忽略
    {
        return NET_ERR_OK;
    }

    // 如果是ACK报文，说明对方在发送数据，但我们处于监听状态，回复RST报文
    if (header->f_ack)
    {
        return tcp_send_reset(seg);
    }

    // 是否是SYN报文，进入SYN_RECEIVED状态并回复ACK+SYN
    if (header->f_syn)
    {
        // 是否超过了连接请求队列长度
        if (tcp_backlog_full(tcp))
        {
            dbug_warn(DBG_MOD_TCP, "TCP listen backlog full");
            return NET_ERR_FULL;
        }

        // 创建一个新的TCP连接来处理这个SYN报文
        tcp_t* new_tcp = tcp_create_child(tcp, seg);
        if (new_tcp == NULL)
        {
            dbug_error(DBG_MOD_TCP, "Failed to tcp_create_child new TCP connection for SYN");
            return NET_ERR_MEM;
        }
        tcp_send_syn(new_tcp);
        return NET_ERR_OK;
    }
    return NET_ERR_STATE;
}

net_err_t tcp_syn_sent_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_ack) // 如果是ACK报文，检查ack_num是否合法
    {
        if (TCP_SEQ_LE(header->ack_num, tcp->send.isn) || TCP_SEQ_LT(tcp->send.next_seq, header->ack_num))
        // if (header->ack_num - tcp->send.isn <= 0 || header->ack_num - tcp->send.next_seq > 0)
        {
            dbug_warn(DBG_MOD_TCP, "Received ACK with invalid ack_num: %u", header->ack_num);
            return tcp_send_reset(seg);
        }
    }

    if (header->f_rst) // 如果是RST报文，关闭连接
    {
        if (!header->f_ack)
        {
            return NET_ERR_OK;
        }
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 如果是SYN报文，进入SYN_RECEIVED状态并回复ACK+SYN
    {
        tcp->recv.isn = header->seq_num;
        tcp->recv.next_seq = header->seq_num + 1;
        tcp->flags.irs_valid = 1;

        tcp_read_options(tcp, header);

        if (header->f_ack)
        {
            tcp_ack_process(tcp, seg);
        }

        // if (tcp->send.un_ack_seq - tcp->send.isn > 0)
        if (TCP_SEQ_LT(tcp->send.isn, tcp->send.un_ack_seq))
        {
            tcp_send_ack(tcp, seg);
            tcp_set_state(tcp, TCP_STATE_ESTABLISHED);
            sock_wakeup(&tcp->base, SOCK_WAIT_CONN, NET_ERR_OK);
        }
        else
        {
            tcp_set_state(tcp, TCP_STATE_SYN_RECEIVED);
            tcp_send_syn(tcp);
        }
    }

    return NET_ERR_OK;
}

net_err_t tcp_syn_received_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in SYN_RECEIVED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in SYN_RECEIVED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (tcp_ack_process(tcp, seg) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in SYN_RECEIVED state");
        return tcp_abort(tcp, NET_ERR_FRAME);
    }

    if (header->f_fin) // 收到FIN报文
    {
        // 按RFC 793，应该转入 CLOSE_WAIT
        dbug_error(DBG_MOD_TCP, "Received FIN in SYN_RECEIVED state");
        return tcp_abort(tcp, NET_ERR_FRAME);
    }

    tcp_set_state(tcp, TCP_STATE_ESTABLISHED);
    if (tcp->parent)
    {
        sock_wakeup(&tcp->parent->base, SOCK_WAIT_CONN, NET_ERR_OK);
    }
    return NET_ERR_OK;
}

net_err_t tcp_established_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;

    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    net_err_t err = NET_ERR_OK;
    if ((err = tcp_ack_process(tcp, seg)) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in ESTABLISHED state");
        return err;
    }

    // 处理数据
    tcp_data_in(tcp, seg);

    // 有没有数据需要发送
    tcp_transmit(tcp);

    // 是否是关闭连接的请求
    if (tcp->flags.fin_in)
    {
        tcp_set_state(tcp, TCP_STATE_CLOSE_WAIT);
    }
    return err;
}

static void tcp_time_wait_timeout(net_timer_t* timer, void* arg)
{
    tcp_t* tcp = arg;
    dbug_info(DBG_MOD_TCP, "TCP TIME_WAIT timeout expired, closing connection");
    tcp_free(tcp);
}

void tcp_time_wait(tcp_t* tcp)
{
    tcp_set_state(tcp, TCP_STATE_TIME_WAIT);

    tcp_kill_all_timer(tcp);
    net_timer_add(&tcp->conn.keep_timer, "2msl timer", tcp_time_wait_timeout, tcp, 2 * TCP_TIMEOUT_MSL * 1000, 0);
    sock_wakeup(&tcp->base, SOCK_WAIT_ALL, NET_ERR_CLOSE);
}

net_err_t tcp_fin_wait_1_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;

    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    net_err_t err = NET_ERR_OK;
    if ((err = tcp_ack_process(tcp, seg)) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in ESTABLISHED state");
        return err;
    }

    tcp_data_in(tcp, seg);

    tcp_transmit(tcp);

    if (tcp->flags.fin_out == 0)
    {
        if (tcp->flags.fin_in) // 是否是关闭连接的请求
        {
            tcp_time_wait(tcp);
        }
        else
        {
            tcp_set_state(tcp, TCP_STATE_FIN_WAIT_2);
        }
    }
    else if (tcp->flags.fin_in)
    {
        tcp_set_state(tcp, TCP_STATE_CLOSING);
    }

    return NET_ERR_OK;
}

net_err_t tcp_fin_wait_2_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;

    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    net_err_t err = NET_ERR_OK;
    if ((err = tcp_ack_process(tcp, seg)) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in ESTABLISHED state");
        return err;
    }

    tcp_data_in(tcp, seg);

    // 是否是关闭连接的请求
    if (tcp->flags.fin_in)
    {
        tcp_send_ack(tcp, seg);
        tcp_time_wait(tcp);
    }
    return NET_ERR_OK;
}

net_err_t tcp_close_wait_in(tcp_t* tcp, tcp_seg_t* seg)
{
    return NET_ERR_OK;
}

net_err_t tcp_closing_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    net_err_t err = NET_ERR_OK;
    if ((err = tcp_ack_process(tcp, seg)) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in ESTABLISHED state");
        return err;
    }

    tcp_transmit(tcp);

    if (tcp->flags.fin_out == 0)
    {
        tcp_time_wait(tcp);
    }

    return NET_ERR_OK;
}

net_err_t tcp_last_ack_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    net_err_t err = NET_ERR_OK;
    if ((err = tcp_ack_process(tcp, seg)) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in ESTABLISHED state");
        return err;
    }

    tcp_transmit(tcp);

    if (tcp->flags.fin_out == 0)
    {
        return tcp_abort(tcp, NET_ERR_CLOSE);
    }

    return NET_ERR_OK;
}

net_err_t tcp_time_wait_in(tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_header_t* header = seg->header;
    if (header->f_rst) // 是否是rest报文
    {
        dbug_error(DBG_MOD_TCP, "Received RST in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    if (header->f_syn) // 重复收到syn报文
    {
        dbug_error(DBG_MOD_TCP, "Received duplicate SYN in ESTABLISHED state");
        return tcp_abort(tcp, NET_ERR_REST);
    }

    net_err_t err = NET_ERR_OK;
    if ((err = tcp_ack_process(tcp, seg)) != NET_ERR_OK) // 处理ACK报文
    {
        dbug_warn(DBG_MOD_TCP, "ACK processing failed in ESTABLISHED state");
        return err;
    }

    tcp_transmit(tcp);

    return NET_ERR_OK;
}
