#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntimed_tricks.h"
#include "udp_replicator.h"

/*
 * Callback from netfilter_log framework via nflog_handle_packet. Retrieve ip
 * src, proto, and payload and pass it on to regular processing.
 */
static int
cb_nflog(struct nflog_g_handle *group, struct nfgenmsg *nfmsg,
    struct nflog_data *nfad, void *ctx)
{
	struct sockaddr_storage sastor;
	struct sockaddr_in *sin;
	socklen_t salen;
	struct nfulnl_msg_packet_hdr *pkt_hdr;
	int ethertype;
	char *packet;
	int packet_len;
	struct iphdr *ip;
	struct udphdr *udp;
	int proto;

	pkt_hdr = nflog_get_msg_packet_hdr(nfad);
	ethertype = htons(pkt_hdr->hw_protocol);
	packet_len = nflog_get_payload(nfad, &packet);
	AN(packet_len > 0);
	switch (ethertype) {
	case 0x0800:
		ip = (struct iphdr *)packet;
		AN(sizeof(*ip) <= packet_len);
		sin = (struct sockaddr_in *)&sastor;
		salen = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip->saddr;
		proto = ip->protocol;
		AN(ip->ihl * 4 <= packet_len);
		packet += ip->ihl * 4;
		packet_len -= ip->ihl * 4;
		AN(proto == 17 && sizeof(*udp) <= packet_len);
		udp = (struct udphdr *)packet;
		AN(ntohs(udp->uh_ulen) == packet_len);
		sin->sin_port = udp->uh_sport;
		packet += sizeof(*udp);
		packet_len -= sizeof(*udp);
		break;
	case 0x86dd:
		WRONG("IPv6 not implemented");
		return 0;
	default:
		WRONG("Bad ethertype received");
		return 0;
	}
	process_packet(packet, packet_len, (struct sockaddr *)&sastor, salen);
	return 0;
}


struct nflog_handle *nflog;
struct nflog_g_handle *group;

void *
open_nflog(int groupnumber)
{
	int opt;

	AN(nflog = nflog_open());
	AZ(nflog_unbind_pf(nflog, AF_INET));
	AZ(nflog_unbind_pf(nflog, AF_INET6));
	AZ(nflog_bind_pf(nflog, AF_INET));

	AN(group = nflog_bind_group(nflog, groupnumber));
	AZ(nflog_set_mode(group, NFULNL_COPY_PACKET, 0xffff));
	AZ(nflog_set_nlbufsiz(group, 8192));
	AZ(nflog_set_timeout(group, 0));
	opt = 1;
	AZ(setsockopt(nflog_fd(nflog), SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(opt)));
	AZ(nflog_callback_register(group, cb_nflog, NULL));

	return nflog;
}

int
processing_one_nflog(struct nflog_handle *nflog)
{
	char buf[8192];
	ssize_t len;

	printf("Line %d\n", __LINE__);
	len = recv(nflog_fd(nflog), buf, sizeof(buf), 0);
	AN(len > 0);
	nflog_handle_packet(nflog, buf, len);
	return 0;
}

