#ifndef DUMP_INET_DIAG_MSG_H
#define DUMP_INET_DIAG_MSG_H

#include <linux/inet_diag.h>
#include <arpa/inet.h>

void dump_inet_diag_msg(struct inet_diag_msg *msg);

//https://elixir.bootlin.com/linux/v3.8/source/include/uapi/linux/inet_diag.h#L13 inet_diag_msg
//https://elixir.bootlin.com/linux/v3.8/source/include/uapi/linux/inet_diag.h#L86 inet_diag_msg.id is inet_diag_sockid
void dump_inet_diag_msg(struct inet_diag_msg *msg) {
	char src_ip_buf[INET6_ADDRSTRLEN];
	char dst_ip_buf[INET6_ADDRSTRLEN]; // lazy, use if else to differentiate ipv4/6
	int  src_port_buf;
	int  dst_port_buf;

	inet_ntop(AF_INET, &msg->id.idiag_src, src_ip_buf, sizeof(src_ip_buf));
	inet_ntop(AF_INET, &msg->id.idiag_dst, dst_ip_buf, sizeof(dst_ip_buf));
	src_port_buf = ntohs(msg->id.idiag_sport);
	dst_port_buf = ntohs(msg->id.idiag_dport);


	printf("src:%16s:%d ", src_ip_buf, src_port_buf);
	printf("dst:%16s:%d ", dst_ip_buf, dst_port_buf);
}


#endif
