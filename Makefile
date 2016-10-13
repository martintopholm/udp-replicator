CC=clang
CFLAGS+=-Wall

udp_replicator: udp_replicator.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^$>

clean:
	rm -f udp_replicator
