CFLAGS ?= -O2 -Wall -g
CC ?= gcc
INSTDIR=/usr/local/bin

latency: latency.c tun.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ -pthread

clean::
	rm -f latency

install:: latency
	umask 022 && cp $< $(INSTDIR)
	chown root: $(INSTDIR)/$<
	chmod 4751 $(INSTDIR)/$<
