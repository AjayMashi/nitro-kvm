/*
 * nitro_output.c
 *
 *  (Re-)Created on: Feb 7, 2012
 *      Author: kirschju
 */

#include <linux/string.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include "nitro.h"
#include "nitro_output.h"

#ifdef USE_NETLINK
struct sock *nl_socket;

u32 len;
u16 pid;
#endif

#ifdef USE_NETLINK
void nl_data_ready(struct sk_buff *skb) {
	printk("Received data from userspace via netlink. This will be ignored ...\n");
}
#endif

int nitro_output_init(void) {
#ifdef USE_NETLINK
	nl_socket = netlink_kernel_create(&init_net, NETLINK_NITRO, 1 << NETLINK_MC_GROUP, nl_data_ready, NULL, THIS_MODULE);
	printk("netlink socket created.\n");
#endif
	return 0;
}

int nitro_output_exit(void) {
#ifdef USE_NETLINK
	netlink_kernel_release(nl_socket);
#endif
	return 0;
}

int nitro_output_append(char *msg) {
#ifdef USE_NETLINK

	struct nlmsghdr *nl_header;
	struct sk_buff *buf;

	buf = alloc_skb(NLMSG_SPACE(OUTPUT_MAX_CHARS), GFP_KERNEL);
	if (!buf) printk("failed to allocate sock buffer\n");

	nl_header = nlmsg_put(buf, 0, 0, 0, NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr), 0);
	NETLINK_CB(buf).pid = 0;

	printk("sending message %s", msg);
	strcpy(NLMSG_DATA(nl_header), msg);
	if (nl_socket == NULL || buf == NULL) {
		nlmsg_multicast(nl_socket, buf, 0, 1 << NETLINK_MC_GROUP, MSG_DONTWAIT);
	} else {
		printk("message dumped.\n");
	}
	kfree(buf);
#else
	printk(msg);
#endif
	return 0;
}
