/* We keep this file for aesthetic enjoyment.
 * Contributions are welcome if they improve the clarity of the code.
 * Feel free to add insightful comments.
 */

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h> // RTA_* macros for struct rtattr (optinoal attributes after the nlmsghdr)
#include <linux/netlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

//inspired by libnml git://git.netfilter.org/libmnl
#define SOCKET_BUFFER_SIZE ( sysconf(_SC_PAGESIZE) < 8192L ? sysconf(_SC_PAGESIZE) : 8192L )

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

#define TCPF_ALL 0xFFF

int main() { // takes no args for now, replace with (int argc, char *argv[]) later
	//printf("%d\n", netlink_socket);
	struct iovec iov[2] = {0};

	struct nlmsghdr nlhdr = {
		.nlmsg_len   = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2)),
		.nlmsg_type  = SOCK_DIAG_BY_FAMILY, //sock_diag.c: if nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY .. dump(skb, nlh)
		.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST, // try NLM_F_ROOT instead of dump
		.nlmsg_seq   = 420, // the kernel doesn't care about these
		.nlmsg_pid   = 69,
	};
	iov[0].iov_base = (void *) &nlhdr;     //nlmsghdr is encapsulated in the msghdr
	iov[0].iov_len  = sizeof(nlhdr);

	struct inet_diag_req_v2 nlreq = {
		.sdiag_family   = AF_INET,
		.sdiag_protocol = IPPROTO_TCP,
		.idiag_ext      = (1 << (INET_DIAG_INFO - 1)), // see the "if (tcp_info)" line in "net/ipv4/inet_diag.c
		.idiag_states   = 0xFFF, // TCPF_ALL
	};
	iov[1].iov_base = (void *) &nlreq;     //inet_diag_req_v2 is encapsulated in the msghdr
	iov[1].iov_len  = sizeof(nlreq);

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_pid    = 0, // usually the pid of the destination process, but 0 means kernel
		.nl_groups = 0, // multicast group mask
	};

	struct msghdr msg = {
		.msg_name    = (void *) &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov     = iov,          // pointer to array of "io vector" structs
		.msg_iovlen  = 2,            // number of elements in the array
	};

	int netlink_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG); // see man 7 netlink
	uint8_t buf[SOCKET_BUFFER_SIZE]; // = {0}; ERROR variable-sized object may not be initialized
	sendmsg(netlink_socket, &msg, 0);

	int i = 0;

	while(1) {
		ssize_t msglen = recv(netlink_socket, buf, sizeof(buf), 0);
		struct nlmsghdr *recvnlh = (struct nlmsghdr *) buf;
		while(NLMSG_OK(recvnlh, msglen)) {
			if(recvnlh->nlmsg_type == NLMSG_DONE) {
				printf(" Done\n");
				return EXIT_SUCCESS;
			} else if(recvnlh->nlmsg_type == NLMSG_ERROR) { //Wou%ld NLMSG_OK equal 1 if there was an error?
				printf("Error\n");
				return EXIT_FAILURE;
			}
			struct inet_diag_msg *diag_msg = (struct inet_diag_msg *) NLMSG_DATA(recvnlh);
			char src_addr_buf[INET_ADDRSTRLEN];
			printf("src:%-16s ", inet_ntop(AF_INET, &diag_msg->id.idiag_src, src_addr_buf, sizeof(buf)));
			struct rtattr *attr = (struct rtattr *) (diag_msg + 1);
			unsigned int rtattrlen = recvnlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
			while (RTA_OK(attr, rtattrlen)) {
				if (attr->rta_type == INET_DIAG_INFO) {
					struct tcp_info *tcpi = (struct tcp_info *) RTA_DATA(attr);
					//https://elixir.bootlin.com/linux/v5.3.8/source/include/uapi/linux/tcp.h#L206
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
				}
				attr = RTA_NEXT(attr, rtattrlen);
			}
			recvnlh = NLMSG_NEXT(recvnlh, msglen);
		}
	}
}
