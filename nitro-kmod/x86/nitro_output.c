/*
 * nitro_output.c
 *
 *  (Re-)Created on: Feb 7, 2012
 *      Author: kirschju
 */

#include <linux/kvm_host.h>
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
	char msgbuf[NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr) + 1];

	nl_header = nlmsg_hdr(skb);
	len = skb->len;

	if(NLMSG_OK(nl_header, len)) {
		memcpy(msgbuf, NLMSG_DATA(nl_header), NLMSG_ALIGN(NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr)));
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
		NITRO_OUTPUT(NETLINK_EXIT);
		//netlink_clear_multicast_users(nl_socket, 1 << NETLINK_MC_GROUP);

		netlink_kernel_release(nl_socket);
	}
#endif
	return 0;
}

void nitro_print_hexdump(u8 *data, int len) {
		int i, j, k;
		for (i = 0; i < len / NITRO_HEXDUMP_BPL; i++) {
			printk("%02X", *(data + i * NITRO_HEXDUMP_BPL));
			for (k = 1; k < NITRO_HEXDUMP_BPL; k++)
				printk(" %02X", *(data + i * NITRO_HEXDUMP_BPL + k));
			printk("\n");
		}
		for (j = 0; j < len % NITRO_HEXDUMP_BPL; j++) {
			printk("%02X ", *(data + i * NITRO_HEXDUMP_BPL + j));
		}
		printk("\n");
}

int nitro_output_data(u8 *data, int length, int type) {
#ifdef USE_NETLINK

	struct nlmsghdr *nl_header;
	struct sk_buff *buf;
	int err = 0;

	/* No data given */
	if (data == NULL) return -4;

	/* System is not initialized */
	if (nl_socket == NULL) return -1;
	
	/* Data does not fit into one fixed-length netlink packet */ 
	/* TODO: Fragment packets accordingly ... */
	if ((type == NITRO_MSG_TYPE_BINARY && length > (NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr)))
		|| (type == NITRO_MSG_TYPE_TEXT && strlen(data) > (NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr))))
		return -5;

	/* No user space process registered yet */
	/* if (netlink_has_listeners(nl_socket, 1 << NETLINK_MC_GROUP) == 0) return -2; */
	/* TODO: Should be called for performance reasons, however expect kernel panics 
	 * due to race conditions when commenting in the line above */

	buf = alloc_skb(NLMSG_SPACE(OUTPUT_MAX_CHARS), GFP_KERNEL);
	if (!buf) {
		printk("WARNING: Failed to allocate netlink socket buffer.\n");
		return -2;
	}

	nl_header = nlmsg_put(buf, 0, 0, 0, NLMSG_SPACE(OUTPUT_MAX_CHARS) - sizeof(struct nlmsghdr), 0);

	/* Sender is _the_kernel_! */
	NETLINK_CB(buf).pid = 0;
	
	/* Set nlmsg_type to signal whether we're sending human readable or binary to the user. */
	nl_header->nlmsg_type = type;
	
	if (type == NITRO_MSG_TYPE_BINARY)
		memcpy((u8 *)NLMSG_DATA(nl_header), data, length);
	if (type == NITRO_MSG_TYPE_TEXT)
		strcpy((u8 *)NLMSG_DATA(nl_header), data);
	
	/* Update headerfield packetsize */
	nlmsg_end(buf, nl_header);
	
	/* Broadcast! Note that only userspace programms with UID = 0 will receive it. */
	err = nlmsg_multicast(nl_socket, buf, 0, 1 << NETLINK_MC_GROUP, MSG_DONTWAIT);
	
	if (err) {
		printk("WARNING: netlink message dropped");
		if (type == NITRO_MSG_TYPE_BINARY) {
			printk(":\n");
			nitro_print_hexdump(data, length);
		} else {
			printk(":\n\"%s\"\n", data);
		}
		return -3;
	}
	
#else
	if (type == NITRO_MSG_TYPE_BINARY) {
		nitro_print_hexdump(data, length);
	} else if (type == NITRO_MSG_TYPE_TEXT) {
		printk("%s", data);
	}
#endif
	return 0;
}
