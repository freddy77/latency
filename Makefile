CFLAGS ?= -O2 -Wall
CC ?= gcc

latency: latency.c client.c tun.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ -pthread

clean::
	rm -f latency
