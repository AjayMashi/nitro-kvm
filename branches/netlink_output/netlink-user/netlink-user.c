#include <sys/capability.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define NETLINK_NITRO 		26
#define NETLINK_MC_GROUP	13
#define MAX_PAYLOAD 		1024
#define NETLINK_START		"NITRO_NETLINK_START"
#define NETLINK_EXIT		"NITRO_NETLINK_EXIT"

#define NITRO_NLMSG_TYPE_BINARY	0
#define NITRO_NLMSG_TYPE_TEXT	1

#define SOL_NETLINK		270 /* only defined for the kernel */
#define MAX_LINKS		32 /* see netlink.h */

#if NETLINK_NITRO > MAX_LINKS
#define NETLINK_NITRO MAX_LINKS
#endif

/* Install libcap-dev */

struct sockaddr_nl nl_src_addr, nl_dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int nl_fd, group;
struct msghdr nl_msg;
char recvbuf[MAX_PAYLOAD];

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

void recvnlmsg(char *buffer) {
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	recvmsg(nl_fd, &nl_msg, 0);
	memcpy(buffer, NLMSG_DATA(nlh), NLMSG_ALIGN(NLMSG_SPACE(MAX_PAYLOAD) - sizeof(struct nlmsghdr)));
	printf("nlmsg_type: %d\n", nlh->nlmsg_type);
	if (nlh->nlmsg_type == NITRO_NLMSG_TYPE_BINARY)
		printf("%08X %08X\n", *(int *)buffer, *((int *)(buffer + 4)));
	if (nlh->nlmsg_type == NITRO_NLMSG_TYPE_TEXT)
		printf("%s", buffer);
}

void init_nl()
{
	group = 1 << NETLINK_MC_GROUP;
	
	nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NITRO);
	memset(&nl_msg, 0, sizeof(nl_msg));
	
	memset(&nl_src_addr, 0, sizeof(nl_src_addr));
	nl_src_addr.nl_family = AF_NETLINK;
	nl_src_addr.nl_pid = getpid();
	nl_src_addr.nl_groups = 1 << NETLINK_MC_GROUP;

	bind(nl_fd, (struct sockaddr *) &nl_src_addr, sizeof(nl_src_addr));
	setsockopt(nl_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
	
	memset(&nl_dest_addr, 0, sizeof(nl_src_addr));
	nl_dest_addr.nl_family = AF_NETLINK;
	nl_dest_addr.nl_pid = 0;
	nl_dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));

	sendnlmsg(NETLINK_START);
	
	do {
		recvnlmsg(recvbuf);
	} while (strcmp(recvbuf, NETLINK_EXIT) != 0);
	printf("\n");
}

static void cleanup_on_int(int signo, struct siginfo *si, void *ctx)
{
	printf("Caught signal %d\n",signo);
	printf("Cleanup, please wait ...\n");
	
	setsockopt(nl_fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &group, sizeof(group));
	
	exit(signo);
}

void installSignalHandler() 
{
	struct sigaction sa;
	
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGINT);

	sa.sa_flags = SA_ONESHOT | SA_SIGINFO;
	sa.sa_sigaction = cleanup_on_int;
	
	if (sigaction(SIGINT, &sa, NULL))
	{
		printf("sigaction failed, line %d, %d/%s\n", __LINE__, errno, strerror(errno));
		exit(2);
	}
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
		printf("FATAL: Need to run as root or have the CAP_NET_ADMIN capability to listen for netlink multicasts. Aborting ...\n");
		return -1;
	}

	installSignalHandler();
	init_nl();
	
	return 0;
}