#include <sys/capability.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NETLINK_NITRO 		26
#define MAX_PAYLOAD 		1024
#define SOL_NETLINK		270
#define NETLINK_MC_GROUP	13
#define NETLINK_EXIT		"NITRO_NETLINK_EXIT"

/* Install libcap-dev */

struct sockaddr_nl nl_src_addr, nl_dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int nl_fd;
struct msghdr nl_msg;
char recvbuf[1024];

void sendnlmsg(const char *message)
{
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD)); 
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy((char *)NLMSG_DATA(nlh), message);

	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;
	nl_msg.msg_name = (void *) &nl_dest_addr;
	nl_msg.msg_namelen = sizeof(nl_dest_addr);
	nl_msg.msg_iov = &iov;
	nl_msg.msg_iovlen = 1;

	sendmsg(nl_fd, &nl_msg, 0);
}

void recvnlmsg(char *message)
{
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	recvmsg(nl_fd, &nl_msg, 0);
	strcpy(message, NLMSG_DATA(nlh));
}

void init_nl()
{
	int group = 1 << NETLINK_MC_GROUP;
	
	nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NITRO);
	memset(&nl_msg, 0, sizeof(nl_msg));
	
	memset(&nl_src_addr, 0, sizeof(nl_src_addr));
	nl_src_addr.nl_family = AF_NETLINK;
	nl_src_addr.nl_pid = getpid();
	nl_src_addr.nl_groups = 1 << NETLINK_MC_GROUP;

	bind(nl_fd, (struct sockaddr*) &nl_src_addr, sizeof(nl_src_addr));
	setsockopt(nl_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
	
	memset(&nl_dest_addr, 0, sizeof(nl_src_addr));
	nl_dest_addr.nl_family = AF_NETLINK;
	nl_dest_addr.nl_pid = 0;
	nl_dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));

	sendnlmsg("Greeting from User!\n");
	
	do {
		recvnlmsg(recvbuf);
		printf("%s",recvbuf);
	} while (strcmp(recvbuf, NETLINK_EXIT) != 0);
	printf("\n");
}

int main()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data;

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = _LINUX_CAPABILITY_VERSION;
	if (capget(&hdr, &data) < 0) {
		printf("capget() failed\n");
	}
	printf("Checking capabilities ...\n");
	printf("Running with uid = %d\n", getuid());
	printf("CAP_NET_ADMIN effective = %d\n", (data.effective & CAP_TO_MASK(CAP_NET_ADMIN)) > 0);
	printf("CAP_NET_ADMIN permitted = %d\n", (data.permitted & CAP_TO_MASK(CAP_NET_ADMIN)) > 0);
	
	if (getuid() != 0 
	&& (data.effective & CAP_TO_MASK(CAP_NET_ADMIN)) == 0
	&& (data.permitted & CAP_TO_MASK(CAP_NET_ADMIN)) == 0) {
		printf("FATAL: Need to run as root or have the CAP_NET_ADMIN capability to listen to netlink multicasts. Aborting ...\n");
		return -1;
	}
	
	
	init_nl();
	
	return 0;
}