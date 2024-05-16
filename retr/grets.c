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
#include <maxminddb.h>

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
	char isp[128];
	uint32_t ASN;
	unsigned int snd_mss;
	unsigned int rcv_mss;
	unsigned int advmss;
	unsigned int pmtu;
};

int socket_count = 0;
struct socket_retr retr_list[6553500]; // TODO dynamic

void store_retr(struct tcp_info* tcpi, struct inet_diag_msg *diag_msg, MMDB_s mmdb) {

	if ( (tcpi->tcpi_bytes_sent != 0) && (tcpi->tcpi_bytes_retrans != 0) ) {
		struct socket_retr *entry = &retr_list[socket_count++];
		inet_ntop(AF_INET, &diag_msg->id.idiag_src, entry->src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &diag_msg->id.idiag_dst, entry->dst_ip, INET6_ADDRSTRLEN);
		entry->bytes_retr = tcpi->tcpi_bytes_retrans;
		entry->bytes_sent = tcpi->tcpi_bytes_sent;
		entry->retr_ratio = ((tcpi->tcpi_bytes_retrans * 100.0) / tcpi->tcpi_bytes_sent );

		int gai_error, mmdb_error;
		MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, entry->dst_ip, &gai_error, &mmdb_error);
		if (gai_error != 0) fprintf(stderr, "Error from getaddrinfo for %s\n", entry->dst_ip);
		if (mmdb_error != MMDB_SUCCESS) fprintf(stderr, "mmdb_error: %s\n", MMDB_strerror(mmdb_error));

		MMDB_entry_data_s entry_data;
		int status = MMDB_get_value(&result.entry, &entry_data, "isp", NULL);
		if (status != MMDB_SUCCESS) fprintf(stderr, "MMDB_get_value failed\n");
		if (entry_data.has_data) {
			strncpy(entry->isp, entry_data.utf8_string, entry_data.data_size);
		} else strcpy(entry->isp, "unknow");

		MMDB_entry_data_s entry_data_asn;
		int status_get_asn = MMDB_get_value(&result.entry, &entry_data_asn, "autonomous_system_number", NULL);
		if (status_get_asn != MMDB_SUCCESS) fprintf(stderr, "MMDB_get_value failed\n");
		if (entry_data.has_data)
			entry->ASN = entry_data_asn.uint32;

		entry->snd_mss = tcpi->tcpi_snd_mss;
		entry->rcv_mss = tcpi->tcpi_rcv_mss;
		entry->advmss = tcpi->tcpi_advmss;
		entry->pmtu = tcpi->tcpi_pmtu;

	}
}

int compare(const void *a, const void *b) {
	struct socket_retr *entry_a = (struct socket_retr *) a;
	struct socket_retr *entry_b = (struct socket_retr *) b;
	//return (entry_a->bytes_retr - entry_b->bytes_retr);
	return (entry_a->retr_ratio - entry_b->retr_ratio);
}

void print_list() {
	qsort(retr_list, socket_count, sizeof(struct socket_retr), compare);

	for (int i = 0; i < socket_count; i++) {
		struct socket_retr *entry = &retr_list[i];
		printf("%16s ",    entry->src_ip);
		printf("%16s ",    entry->dst_ip);
		printf("%16lu ",     entry->bytes_retr);
		printf("%16lu ",     entry->bytes_sent);
		printf("%6.2f%% ", entry->retr_ratio);
		printf("%4u ", entry->snd_mss);
		printf("%7u ", entry->rcv_mss);
		printf("%6u ", entry->advmss);
		printf("%5u ", entry->pmtu);
		printf("%6u ", entry->ASN);
		printf("%6s ", entry->isp);
		printf("\n");
	}
}

void print_legend() {
		printf("%16s ",    "src_ip");
		printf("%16s ",    "dst_ip");
		printf("%16s ",    "bytes_retr");
		printf("%16s ",   "bytes_sent");
		printf("%5s ", "  retr%");
		printf("%7s ", "sndmss");
		printf("%7s ", "rcvmss");
		printf("%6s ", "advmss");
		printf("%5s ", "pmtu");
		printf("%6s ", "ASN");
		printf("%6s ", "isp");
		printf("\n");
}

int main(int argc, char *argv[]) { // TODO getopt_long for flags

	MMDB_s mmdb;
	int status = MMDB_open("/usr/share/GeoIP/GeoIP2-ISP.mmdb", MMDB_MODE_MMAP, &mmdb);
	if (MMDB_SUCCESS != status) {
		fprintf(stderr, "\n Can't open %s - %s\n", "/usr/share/GeoIP/GeoIP2-ISP.mmdb", MMDB_strerror(status));
		return EXIT_FAILURE;
	}

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
		while(NLMSG_OK(recvnlh, msglen)) {
			if(recvnlh->nlmsg_type == NLMSG_DONE){
				print_list();
				print_legend();
				return EXIT_SUCCESS;
			}
			else if(recvnlh->nlmsg_type == NLMSG_ERROR)
				return EXIT_FAILURE;
			struct inet_diag_msg *diag_msg = (struct inet_diag_msg *) NLMSG_DATA(recvnlh);
			struct rtattr *attr = (struct rtattr *) (diag_msg + 1);
			unsigned int rtattrlen = recvnlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
			while (RTA_OK(attr, rtattrlen)) {
				if (attr->rta_type == INET_DIAG_INFO) {
					struct tcp_info *tcpi = (struct tcp_info *) RTA_DATA(attr);
					store_retr(tcpi, diag_msg, mmdb); // include/uapi/linux/tcp.h#L206
				}
				attr = RTA_NEXT(attr, rtattrlen);
			}
			recvnlh = NLMSG_NEXT(recvnlh, msglen);
		}
	}
}
