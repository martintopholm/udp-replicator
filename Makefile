CFLAGS+=-Wall
OBJS=udp_replicator.o recv_nflog.o
LIBS=-lnetfilter_log -lnfnetlink

udp_replicator: udp_replicator.o recv_nflog.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@ $^$>

clean:
	rm -f udp_replicator $(OBJS)
