PREFIX?=/usr/local
SBINPATH?=$(PREFIX)/sbin
MANPATH?=$(PREFIX)/man
CFLAGS+=-Wall
LDFLAGS+=
LIBS+=-lnetfilter_log -lnfnetlink
OBJS=udp_replicator.o recv_nflog.o

all: udp_replicator udp_replicator.8.gz

udp_replicator: udp_replicator.o recv_nflog.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^$> $(LIBS)

udp_replicator.8.gz: udp_replicator.8
	gzip -9 -c $^$> > $@

install:
	mkdir -p $(SBINPATH)
	mkdir -p $(MANPATH)/man8
	install -m 555 udp_replicator $(SBINPATH)/
	install -m 444 udp_replicator.8.gz $(MANPATH)/man8/

clean:
	make -C tests clean
	rm -f udp_replicator udp_replicator.8.gz $(OBJS)

test:
	make -C tests tinytest
	env sudo -E ./tests/tinytest
