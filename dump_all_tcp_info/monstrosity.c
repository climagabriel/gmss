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
#include "dump_tcp_info_struct.h"
#include "dump_inet_diag_msg.h"

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

int main(int argc, char *argv[]) { // takes no args for now, replace with (int argc, char *argv[]) later
	//printf("%d\n", netlink_socket);
	//char format = argv[1][0];
	char format;
	if (argc == 1) {
		format = 'l';
	} else { format = argv[1][0];
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
			} else if(recvnlh->nlmsg_type == NLMSG_ERROR) { //Would NLMSG_OK equal 1 if there was an error?
				printf("Error\n");
				return EXIT_FAILURE;
			}
			struct inet_diag_msg *diag_msg = (struct inet_diag_msg *) NLMSG_DATA(recvnlh);
			dump_inet_diag_msg(diag_msg);
			struct rtattr *attr = (struct rtattr *) (diag_msg + 1);
			unsigned int rtattrlen = recvnlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
			while (RTA_OK(attr, rtattrlen)) {
				if (attr->rta_type == INET_DIAG_INFO) {
					struct tcp_info *tcpi = (struct tcp_info *) RTA_DATA(attr);
					//https://elixir.bootlin.com/linux/v5.3.8/source/include/uapi/linux/tcp.h#L206
					dump_tcp_info_struct(tcpi, format);
				}
				attr = RTA_NEXT(attr, rtattrlen);
			}
			recvnlh = NLMSG_NEXT(recvnlh, msglen);
		}
	}
}
