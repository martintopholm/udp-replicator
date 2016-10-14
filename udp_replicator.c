#include <sys/param.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utlist.h"
#include "ntimed_tricks.h"


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

/*
 * Receive a packet and replicate to entries in target_list while using the
 * original sender as source address. Port will be based on the listening
 * socket's sin_port.
 */
int
processing_one_packet(int fd)
{
	struct entry *ent;
	struct msghdr msgh; /* recv(2) */
	struct cmsghdr *cmsg; /* cmsg(3) */
	struct iovec iov;
	char payload[8192];
	char control[1024];
	
	ssize_t payload_len;
	ssize_t sent_bytes;
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

	/*
	 * Rewrite source address if source isn't 127.0.0.0/8 as this may
	 * result in EINVAL when egress non-loopback interface.
	 */
	AN(msgh.msg_namelen == sizeof(src));
	AN(sizeof(src.sin_addr) == sizeof(in_pktinfo->ipi_spec_dst));
	in_pktinfo->ipi_ifindex = 0;
	if (ntohl(src.sin_addr.s_addr) >= 0x7f000001 &&
	    ntohl(src.sin_addr.s_addr) <= 0x7fffffff) {
		memset(&in_pktinfo->ipi_spec_dst, 0,
		    sizeof(in_pktinfo->ipi_spec_dst));
	} else {
		memcpy(&in_pktinfo->ipi_spec_dst, &src.sin_addr,
		    sizeof(in_pktinfo->ipi_spec_dst));
	}

	/*
	 * Adjust iovec length to actual payload size and send with spoofed src
	 * (in_pktinfo->ipi_spec_dst) sending to dst
	 */
	msgh.msg_iov[0].iov_len = payload_len;
	LL_FOREACH(target_list, ent) {
		msgh.msg_name = &ent->sin;
		msgh.msg_namelen = sizeof(ent->sin);
		sent_bytes = sendmsg(fd, &msgh, 0);
		if (sent_bytes < 0) {
			perror("sendmsg()");
		}
		AN(sent_bytes == payload_len);
	}
	return 0;
}


/*
 * Setup a UDP socket and replicate each received packet to target_list.
 */
int
main(int argc, char *argv[])
{
	struct entry *ent;
	struct sockaddr_in sin;
	int fd;
	int one;
	int i;

	target_list = NULL;
	for (i = 1; i < argc; i++) {
		AN(ent = calloc(1, sizeof(*ent)));
		ent->text = strdup(argv[i]);
		AN(inet_pton(AF_INET, argv[i], &ent->sin.sin_addr) == 1);
		ent->sin.sin_family = AF_INET;
		ent->sin.sin_port = htons(514);
		LL_APPEND(target_list, ent);
	}
	if (target_list == NULL) {
		fprintf(stderr, "empty target list\n");
		return 1;
	}

	one = 1;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8514);

	fd = socket(sin.sin_family, SOCK_DGRAM, 17);
	AN(fd >= 0);
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind()");
		return 1;
	}
	AZ(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
	if (setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &one, sizeof(one)) < 0) {
		perror("setsockopt(fd, IPPROTO_IP, ...)");
		return 1;
	}
	AZ(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)));

	for (;;) {
		processing_one_packet(fd);
	}

	return 0;
}

