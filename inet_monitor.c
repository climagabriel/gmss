#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCPF_ESTABLISHED = (1 << 1),
    TCPF_SYN_SENT    = (1 << 2),
    TCPF_SYN_RECV    = (1 << 3),
    TCPF_FIN_WAIT1   = (1 << 4),
    TCPF_FIN_WAIT2   = (1 << 5),
    TCPF_TIME_WAIT   = (1 << 6),
    TCPF_CLOSE       = (1 << 7),
    TCPF_CLOSE_WAIT  = (1 << 8),
    TCPF_LAST_ACK    = (1 << 9),
    TCPF_LISTEN      = (1 << 10),
    TCPF_CLOSING     = (1 << 11) 
};

//There are currently 11 states, but the first state is stored in pos. 1.
//Therefore, I need a 12 bit bitmask
#define TCPF_ALL 0xFFF

//Copied from libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

int send_diag_msg(int sockfd){
    struct msghdr msg;
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 conn_req;
    struct sockaddr_nl sa;
    struct iovec iov[2];

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));

    //NOTE: Bytecode is an nlattr for the request
    conn_req.sdiag_family = AF_INET;
    conn_req.sdiag_protocol = IPPROTO_TCP;

    //Filter out some states, show most relevant states for a client machine
    conn_req.idiag_states = TCPF_ALL & 
        ~(TCPF_SYN_RECV | TCPF_TIME_WAIT | TCPF_CLOSE | TCPF_LISTEN);

    //Request extended TCP information (it is the tcp_info struct)
    //ext is a bitmask containing the extensions I want to acquire
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;

    //Avoid using compat by specifying family + protocol in header
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*) &conn_req;
    iov[1].iov_len = sizeof(conn_req);

    //No need to specify groups or pid. This message only has one receiver and
    //pid 0 is kernel
    sa.nl_family = AF_NETLINK;

    //Set essage correctly
    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
   
    return sendmsg(sockfd, &msg, 0);
}

void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen){
    struct rtattr *attr;
    struct tcp_info *tcpi;
    //In preparation of IPv6 support
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];

    memset(local_addr_buf, 0, sizeof(local_addr_buf));
    memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

    if(diag_msg->idiag_family == AF_INET){
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src), 
            local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst), 
            remote_addr_buf, INET_ADDRSTRLEN);
    } else if(diag_msg->idiag_family == AF_INET6){
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return;
    }

    if(local_addr_buf[0] == 0 || remote_addr_buf[0] == 0){
        fprintf(stderr, "Could not get required connection information\n");
        return;
    } else {
        fprintf(stdout, "Src: %s:%d Dst: %s:%d\n", 
                local_addr_buf, ntohs(diag_msg->id.idiag_sport), 
                remote_addr_buf, ntohs(diag_msg->id.idiag_dport));
    }

    if(rtalen > 0){
        attr = (struct rtattr*) (diag_msg+1);

        //printf("Length: %d %u\n", attr->rta_len, sizeof(struct rtattr));
        while(RTA_OK(attr, rtalen)){
            if(attr->rta_type == INET_DIAG_INFO){
                tcpi = (struct tcp_info*) RTA_DATA(attr);

                //Output some sample data
                fprintf(stdout, "\tRTT: %gms (var. %gms) Recv. RTT: %gms "
                        "Snd_cwnd: %u/%u\n",
                        (double) tcpi->tcpi_rtt/1000, 
                        (double) tcpi->tcpi_rttvar/1000,
                        (double) tcpi->tcpi_rcv_rtt/1000, 
                        tcpi->tcpi_unacked,
                        tcpi->tcpi_snd_cwnd);
            }
            attr = RTA_NEXT(attr, rtalen); 
        }
    }
}

int main(int argc, char *argv[]){
    int nl_sock = 0, numbytes = 0, rtalen = 0;
    struct nlmsghdr *nlh;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;

    //Create the monitoring socket
    if((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
        perror("socket: ");
        return EXIT_FAILURE;
    }

    if(send_diag_msg(nl_sock) < 0){
        perror("sendmsg: ");
        return EXIT_FAILURE;
    }

    while(1){
        numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
        nlh = (struct nlmsghdr*) recv_buf;

        while(NLMSG_OK(nlh, numbytes)){
            if(nlh->nlmsg_type == NLMSG_DONE)
                return EXIT_FAILURE;

            diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
            rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
            parse_diag_msg(diag_msg, rtalen);

            nlh = NLMSG_NEXT(nlh, numbytes); 
        }
    }

    return EXIT_SUCCESS;
}