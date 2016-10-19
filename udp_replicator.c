#include <sys/param.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ntimed_tricks.h"
#include "recv_nflog.h"
#include "utlist.h"


/*
 * References
 * http://stackoverflow.com/questions/3062205/setting-the-source-ip-for-a-udp-socket
 * https://www.mjmwired.net/kernel/Documentation/networking/tproxy.txt
 * https://github.com/pmacct/pmacct/blob/master/src/tee_plugin/tee_recvs.c
 */


struct entry {
	char			*text;
	struct sockaddr_in	sin;
	void			*next;
};

struct entry *target_list;
int udp_socket;

#define sin_is_loopback(x) ( \
    (ntohl((x)->sin_addr.s_addr) & 0xff000000) == 0x7f000000)

void
process_packet(char *payload, size_t payload_len,
    struct sockaddr *sa_src, socklen_t sa_srclen, void *ctx)
{
	char cmsg_buf[1024];
	struct msghdr msg[1];
	struct iovec iov[1];
	struct cmsghdr *cmsg;
	struct in_pktinfo *in_pktinfo;
	size_t cmsg_length;
	struct sockaddr_in *src;
	struct entry *ent;
	ssize_t sent_bytes;

	AN(sa_src->sa_family == AF_INET &&
	    sa_srclen == sizeof(struct sockaddr_in));
	src = (struct sockaddr_in *)sa_src;
	iov->iov_base = payload;
	iov->iov_len = payload_len;
	msg->msg_name = NULL; /* filled out in send loop */
	msg->msg_namelen = 0;
	msg->msg_iov = iov;
	msg->msg_iovlen = 1;
	msg->msg_control = cmsg_buf;
	msg->msg_controllen = sizeof(cmsg_buf);

	/* Prepare IP_PKTINFO and copy source when it isn't the loopback. */
	cmsg_length = 0;
	cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*in_pktinfo));
	cmsg_length += CMSG_SPACE(sizeof(*in_pktinfo));
	in_pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
	memset(in_pktinfo, 0, sizeof(*in_pktinfo));
	if (!sin_is_loopback(src)) {
		memcpy(&in_pktinfo->ipi_spec_dst, &src->sin_addr,
		    sizeof(in_pktinfo->ipi_spec_dst));
	}
	msg->msg_controllen = cmsg_length;

	LL_FOREACH(target_list, ent) {
		printf("%s %d\n", ent->text, ntohs(ent->sin.sin_port));
		msg->msg_name = &ent->sin;
		msg->msg_namelen = sizeof(ent->sin);
		sent_bytes = sendmsg(udp_socket, msg, 0);
		if (sent_bytes < 0) {
			perror("sendmsg()");
		}
		AN(sent_bytes == payload_len);
	}
}

/*
 * Receive a packet and replicate to entries in target_list while using the
 * original sender as source address. Port will be based on the listening
 * socket's sin_port.
 */
void
processing_one_packet(int fd)
{
	struct msghdr msgh; /* recv(2) */
	struct cmsghdr *cmsg; /* cmsg(3) */
	struct iovec iov;
	char payload[8192];
	char control[1024];
	ssize_t payload_len;
	struct in_pktinfo *in_pktinfo;

	struct sockaddr_in src;

	/* Receive packet payload and sender information */
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);
	msgh.msg_name = &src;
	msgh.msg_namelen = sizeof(src);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = control;
	msgh.msg_controllen = sizeof(control);
	payload_len = recvmsg(fd, &msgh, 0);
	printf("len=%zd errno=%d\n", payload_len, errno);
	AN(payload_len > 0);
	in_pktinfo = NULL;
	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP
		    && cmsg->cmsg_type == IP_PKTINFO) {
			in_pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
			break;
		}
	}
	AN(cmsg != NULL);
	AN(in_pktinfo != NULL);

	process_packet(payload, payload_len, msgh.msg_name, msgh.msg_namelen, NULL);
}


static int
parse_sockaddr(char *str, struct sockaddr_in *sin)
{
	char *ptr_port;
	char *end;
	int port;

	port = 0;
	ptr_port = strchr(str, ':');
	if (ptr_port != NULL) {
		*ptr_port = '\0';
		ptr_port += 1;
		port = strtol(ptr_port, &end, 10);
		if (*ptr_port != '\0' && *end != '\0')
			return -1;
		if (port < 0 || port > 65535)
			return -1;
	}
	sin->sin_family = AF_INET;
	if (inet_pton(AF_INET, str, &sin->sin_addr) != 1)
		return -1;
	sin->sin_port = htons(port);
	return 0;
}

void
free_list(struct entry *list)
{
	struct entry *ent;
	struct entry *tmp;

	LL_FOREACH_SAFE(list, ent, tmp) {
		if (ent->text != NULL)
			free(ent->text);
		free(ent);
	}
}

static struct entry *
setup_list(int argc, char *argv[])
{
	struct entry *list;
	struct entry *ent;
	int i;
	struct sockaddr_in sin;

	list = NULL;
	for (i = 0; i < argc; i++) {
		if (parse_sockaddr(argv[i], &sin) < 0) {
			fprintf(stderr, "unable to parse %s\n", argv[i]);
			free_list(list);
			return NULL;
		}
		if (sin.sin_port == 0) {
			fprintf(stderr, "port not specified for %s\n",
			    argv[i]);
			free_list(list);
			return NULL;
		}
		AN(ent = calloc(1, sizeof(*ent)));
		ent->text = strdup(argv[i]);
		memcpy(&ent->sin, &sin, sizeof(ent->sin));
		LL_APPEND(list, ent);
	}
	return list;
}

static int
setup_socket(unsigned short udp_port)
{
	struct sockaddr_in sin;
	int fd;
	int one;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	if (udp_port > 0)
		sin.sin_port = htons(udp_port);
	fd = socket(sin.sin_family, SOCK_DGRAM, 17);
	AN(fd >= 0);
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		return -1;
	}
	one = 1;
	AZ(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
	if (setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &one, sizeof(one)) < 0) {
		return -1;
	}
	AZ(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)));

	return fd;
}

static void
err(int eval, char *whine)
{

	perror(whine);
	exit(eval);
}

static void
usage(char *whine)
{
	if (whine != NULL)
		fprintf(stderr, "udp_replicator: %s\n", whine);
	fprintf(stderr,
	    "usage: udp_replicator [-h] [-g group] [-p port] "
	    "address [address]\n"
	    "\n");
	exit(1);
}

/*
 * Setup a UDP socket and replicate each received packet to target_list.
 */
int
main(int argc, char *argv[])
{
	struct recv_nflog *rcv;
	int fd;
	int nflog_group;
	int udp_port;
	char *end;
	int ch;

	nflog_group = 0;
	udp_port = 0;
	while ((ch = getopt(argc, argv, "hg:p:")) != -1) {
		switch (ch) {
		case 'g':
			nflog_group = strtol(optarg, &end, 10);
			if (*optarg != '\0' && *end != '\0')
				usage("invalid group");
			break;
		case 'p':
			udp_port = strtol(optarg, &end, 10);
			if (*optarg != '\0' && *end != '\0')
				usage("invalid udp port");
			if (udp_port < 0 || udp_port > 65535)
				usage("invalid udp port");
			break;
		case 'h':
		default:
			usage(NULL);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage("empty target list");
	target_list = setup_list(argc, argv);
	if (target_list == NULL)
		usage(NULL);
	fd = setup_socket(udp_port);
	if (fd < 0)
		err(2, "setup_socket");
	if (nflog_group) {
		rcv = recv_nflog_new(31, process_packet, NULL);
		if (rcv == NULL)
			err(2, "recv_nflog_new");
	}

	/* Packet processing */
	if (nflog_group) {
		for (;;)
			recv_nflog_packet_dispatch(rcv);
	} else {
		for (;;)
			processing_one_packet(udp_socket);
	}

	if (nflog_group)
		recv_nflog_free(rcv);
	return 0;
}

