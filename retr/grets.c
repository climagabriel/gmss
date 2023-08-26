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
#include <string.h>
#include <getopt.h>
#include <limits.h>

//inspired by libnml git://git.netfilter.org/libmnl
#define SOCKET_BUFFER_SIZE ( sysconf(_SC_PAGESIZE) < 8192L ? sysconf(_SC_PAGESIZE) : 8192L )
#define TCPF_ALL 0xFFF

//https://elixir.bootlin.com/linux/v3.8/source/include/uapi/linux/inet_diag.h#L13 inet_diag_msg
//https://elixir.bootlin.com/linux/v3.8/source/include/uapi/linux/inet_diag.h#L86 inet_diag_msg.id is inet_diag_sockid

struct socket_retr {
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	unsigned long bytes_retr;
	unsigned long bytes_sent;
	float retr_ratio;
};

int socket_count = 0;

struct socket_retr retr_list[65535]; // TODO dynamic

void store_retr(struct tcp_info* tcpi, struct inet_diag_msg *diag_msg) {
	if ( (tcpi->tcpi_bytes_sent != 0) && (tcpi->tcpi_bytes_retrans != 0) ) {
		struct socket_retr *entry = &retr_list[socket_count++];
		inet_ntop(AF_INET, &diag_msg->id.idiag_src, entry->src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &diag_msg->id.idiag_dst, entry->dst_ip, INET6_ADDRSTRLEN);
		entry->bytes_retr = tcpi->tcpi_bytes_retrans;
		entry->bytes_sent = tcpi->tcpi_bytes_sent;
		entry->retr_ratio = ((tcpi->tcpi_bytes_retrans * 100.0) / tcpi->tcpi_bytes_sent );
	}
}

int compare(const void *a, const void *b) {
	struct socket_retr *entry_a = (struct socket_retr *) a;
	struct socket_retr *entry_b = (struct socket_retr *) b;
	return (entry_a->bytes_retr - entry_b->bytes_retr);
}

void print_list() {
	qsort(retr_list, socket_count, sizeof(struct socket_retr), compare);

	for (int i = 0; i < socket_count; i++) {
		struct socket_retr *entry = &retr_list[i];
		printf("%16s ",    entry->src_ip);
		printf("%16s ",    entry->dst_ip);
		printf("%lu ",     entry->bytes_retr);
		printf("%lu ",     entry->bytes_sent);
		printf("%.0f%%\n", entry->retr_ratio);
	}
}

int main(int argc, char *argv[]) { // TODO getopt_long for flags

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
		.idiag_ext      = (1 << (INET_DIAG_INFO - 1)), // | (1 << (INET_DIAG_CONG - 1)) ,
		                                              //  "net/ipv4/inet_diag.c
		.idiag_states   = TCPF_ALL,
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

	while(1) {
		ssize_t msglen = recv(netlink_socket, buf, sizeof(buf), 0);
		struct nlmsghdr *recvnlh = (struct nlmsghdr *) buf;
//		for (int i = 0; NLMSG_OK(recvnlh, msglen); i++) {
		while(NLMSG_OK(recvnlh, msglen)) {
			if(recvnlh->nlmsg_type == NLMSG_DONE){
				printf("check\n");
				print_list();
				return EXIT_SUCCESS;
			}
			else if(recvnlh->nlmsg_type == NLMSG_ERROR) //Would NLMSG_OK equal 1 if there was an error?
				return EXIT_FAILURE;
			struct inet_diag_msg *diag_msg = (struct inet_diag_msg *) NLMSG_DATA(recvnlh);
			struct rtattr *attr = (struct rtattr *) (diag_msg + 1);
			unsigned int rtattrlen = recvnlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
			while (RTA_OK(attr, rtattrlen)) {
				if (attr->rta_type == INET_DIAG_INFO) {
					struct tcp_info *tcpi = (struct tcp_info *) RTA_DATA(attr);
					store_retr(tcpi, diag_msg); // include/uapi/linux/tcp.h#L206
				}
				attr = RTA_NEXT(attr, rtattrlen);
			}
			//printf("%d\n", i);
			recvnlh = NLMSG_NEXT(recvnlh, msglen);
		}
	}
}
