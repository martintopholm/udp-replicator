CC=clang
CFLAGS+=-Wall
LIBS=-lnetfilter_log -lnfnetlink

udp_replicator: udp_replicator.c recv_nflog.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@ $^$>

clean:
	rm -f udp_replicator
