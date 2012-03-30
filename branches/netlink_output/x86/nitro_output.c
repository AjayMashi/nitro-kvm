/*
 * nitro_output.c
 *
 *  (Re-)Created on: Feb 7, 2012
 *      Author: kirschju
 */

#include <linux/string.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include "nitro.h"
#include "nitro_output.h"

#ifdef USE_NETLINK
struct sock *nl_socket;
struct msghdr msg;
u32 len;
#endif

#ifdef USE_NETLINK
void nl_data_ready(struct sk_buff *skb) {
	struct nlmsghdr *nl_header;
	int len;
	char msgbuf[OUTPUT_MAX_CHARS];

	nl_header = nlmsg_hdr(skb);
	len = skb->len;

	if(NLMSG_OK(nl_header, len)) {
		memcpy(msgbuf, NLMSG_DATA(nl_header), sizeof(msg));
		printk("nitro_output:%s: Received data from userspace process: \"%s\"\n", __func__, msgbuf);
	 }
}
#endif

int nitro_output_init(void) {
#ifdef USE_NETLINK
	if (nl_socket) {
		printk("WARNING: Netlink socket already initialized.\n");
		return -2;
	}

	nl_socket = netlink_kernel_create(&init_net, NETLINK_NITRO, 1 << NETLINK_MC_GROUP, nl_data_ready, NULL, THIS_MODULE);
	if (nl_socket == NULL) {
		printk("WARNING: Could not allocate netlink socket.\n");
		return -1;
	}
#endif
	return 0;
}

int nitro_output_exit(void) {
#ifdef USE_NETLINK
	if (nl_socket) {
		/* Deregister all userspace processes */
		nitro_output_append(NETLINK_EXIT);
		//netlink_clear_multicast_users(nl_socket, 1 << NETLINK_MC_GROUP);

		netlink_kernel_release(nl_socket);
	}
#endif
	return 0;
}

int nitro_output_append(char *msg) {
#ifdef USE_NETLINK

	struct nlmsghdr *nl_header;
	struct sk_buff *buf;
	int err;

	/* System is not initialized */
	if (nl_socket == NULL) return -1;

	/* No user space process registered yet */
	if (netlink_has_listeners(nl_socket, 1 << NETLINK_MC_GROUP) == 0) return -2;

	buf = alloc_skb(NLMSG_SPACE(OUTPUT_MAX_CHARS), GFP_KERNEL);
	if (!buf) {
		printk("WARNING: Failed to allocate socket buffer. Not sending this message to user space: \"%s\"", msg);
		return -2;
	}

	nl_header = nlmsg_put(buf, 0, 0, 0, NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr), 0);

	/* Sender is _the_kernel_! */
	NETLINK_CB(buf).pid = 0;

	strcpy(NLMSG_DATA(nl_header), msg);
	err = nlmsg_multicast(nl_socket, buf, 0, 1 << NETLINK_MC_GROUP, MSG_DONTWAIT);
	if (err) {
		printk("WARNING: No user space process received the message \"%s\"", msg);
		return -3;
	}
#else

	printk(msg);
#endif

	return 0;
}
