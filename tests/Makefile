#CFLAGS+=-Wall -Wpedantic -I..
CFLAGS+=-I..
LDFLAGS+=-lnetfilter_log -lnfnetlink -lcap
OBJS=check_recv_nflog.o tests.o tinytest.o ../recv_nflog.o

tinytest: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@ $^$>

clean:
	rm -f $(OBJS)
