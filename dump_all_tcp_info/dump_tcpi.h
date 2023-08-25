#ifndef DUMP_TCP_I_H
#define DUMP_TCP_I_H

#include <linux/tcp.h>
#include <stdio.h>

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

static const char* tcp_states_map[]={ // array of pointers
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

int dump_tcpi(struct tcp_info* tcpi);

int dump_tcpi(struct tcp_info* tcpi) {
	printf("state:%s ca_state:%u retransmits:%u probes:%u backoff:%u options:%u snd_wscale:%u rcv_wscale:%u delivery_rate_app_limited:%u rto:%u ato:%u snd_mss:%u rcv_mss:%u unacked:%u sacked:%u lost:%u retrans:%u fackets:%u last_data_sent:%u last_ack_sent:%u last_data_recv:%u last_ack_recv:%u pmtu:%u rcv_ssthresh:%u rtt:%u rttvar:%u snd_ssthresh:%u snd_cwnd:%u advmss:%u reordering:%u rcv_rtt:%u rcv_space:%u total_retrans:%u pacing_rate:%Lu max_pacing_rate:%Lu bytes_acked:%Lu bytes_received:%Lu segs_out:%u segs_in:%u notsent_bytes:%u min_rtt:%u data_segs_in:%u data_segs_out:%u delivery_rate:%Lu busy_time:%Lu rwnd_limited:%Lu sndbuf_limited:%Lu delivered:%u delivered_ce:%u bytes_sent:%Lu bytes_retrans:%Lu dsack_dups:%u reord_seen:%u ",
                       tcp_states_map[tcpi->tcpi_state],
                       tcpi->tcpi_ca_state,
                       tcpi->tcpi_retransmits,
                       tcpi->tcpi_probes,
                       tcpi->tcpi_backoff,
                       tcpi->tcpi_options,
                       tcpi->tcpi_snd_wscale,
                       tcpi->tcpi_rcv_wscale,
                       tcpi->tcpi_delivery_rate_app_limited,
                       tcpi->tcpi_rto,
                       tcpi->tcpi_ato,
                       tcpi->tcpi_snd_mss,
                       tcpi->tcpi_rcv_mss,
                       tcpi->tcpi_unacked,
                       tcpi->tcpi_sacked,
                       tcpi->tcpi_lost,
                       tcpi->tcpi_retrans,
                       tcpi->tcpi_fackets,
                       tcpi->tcpi_last_data_sent,
                       tcpi->tcpi_last_ack_sent,
                       tcpi->tcpi_last_data_recv,
                       tcpi->tcpi_last_ack_recv,
                       tcpi->tcpi_pmtu,
                       tcpi->tcpi_rcv_ssthresh,
                       tcpi->tcpi_rtt,
                       tcpi->tcpi_rttvar,
                       tcpi->tcpi_snd_ssthresh,
                       tcpi->tcpi_snd_cwnd,
                       tcpi->tcpi_advmss,
                       tcpi->tcpi_reordering,
                       tcpi->tcpi_rcv_rtt,
                       tcpi->tcpi_rcv_space,
                       tcpi->tcpi_total_retrans,
                       tcpi->tcpi_pacing_rate,
                       tcpi->tcpi_max_pacing_rate,
                       tcpi->tcpi_bytes_acked,
                       tcpi->tcpi_bytes_received,
                       tcpi->tcpi_segs_out,
                       tcpi->tcpi_segs_in,
                       tcpi->tcpi_notsent_bytes,
                       tcpi->tcpi_min_rtt,
                       tcpi->tcpi_data_segs_in,
                       tcpi->tcpi_data_segs_out,
                       tcpi->tcpi_delivery_rate,
                       tcpi->tcpi_busy_time,
                       tcpi->tcpi_rwnd_limited,
                       tcpi->tcpi_sndbuf_limited,
                       tcpi->tcpi_delivered,
                       tcpi->tcpi_delivered_ce,
                       tcpi->tcpi_bytes_sent,
                       tcpi->tcpi_bytes_retrans,
                       tcpi->tcpi_dsack_dups,
                       tcpi->tcpi_reord_seen);
	               return 0;
}
#endif
