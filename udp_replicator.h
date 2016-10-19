#ifdef UDP_REPLICATOR_H
#error "udp_replicator.h included multiple times"
#endif
#define UDP_REPLICATOR_H

int process_packet(char *, size_t, struct sockaddr *, socklen_t);
