#ifndef DUMP_TCP_INFO_STRUCT_H
#define DUMP_TCP_INFO_STRUCT_H

#include <linux/tcp.h>
#include <stdio.h>

int dump_tcp_info_struct(struct tcp_info* tcpi);

int dump_tcp_info_struct(struct tcp_info* tcpi) {
	printf("state:%ld ca_state:%ld retransmits:%ld probes:%ld backoff:%ld options:%ld snd_wscale:%ld rcv_wscale:%ld delivery_rate_app_limited:%ld rto:%ld ato:%ld snd_mss:%ld rcv_mss:%ld unacked:%ld sacked:%ld lost:%ld retrans:%ld fackets:%ld last_data_sent:%ld last_ack_sent:%ld last_data_recv:%ld last_ack_recv:%ld pmtu:%ld rcv_ssthresh:%ld rtt:%ld rttvar:%ld snd_ssthresh:%ld snd_cwnd:%ld advmss:%ld reordering:%ld rcv_rtt:%ld rcv_space:%ld total_retrans:%ld pacing_rate:%ld max_pacing_rate:%ld bytes_acked:%ld bytes_received:%ld segs_out:%ld segs_in:%ld notsent_bytes:%ld min_rtt:%ld data_segs_in:%ld data_segs_out:%ld delivery_rate:%ld busy_time:%ld rwnd_limited:%ld sndbuf_limited:%ld delivered:%ld delivered_ce:%ld bytes_sent:%ld bytes_retrans:%ld dsack_dups:%ld reord_seen:%ld\n",
                       tcpi->tcpi_state,
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
