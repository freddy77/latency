CFLAGS ?= -O2 -Wall -g
CC ?= gcc

latency: latency.c tun.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ -pthread

clean::
	rm -f latency
