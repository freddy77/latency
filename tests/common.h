#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/** check if latency executable is running */
bool latency_running(void);

/** launch a program with given parameters */
void launch_latency(const char *fmt, ...);

/** kill latency process */
void kill_latency(void);

typedef union {
	struct sockaddr generic;
	struct sockaddr_in inet;
	struct sockaddr_in6 inet6;
} sockaddr_all;

void setup_addr(sockaddr_all *addr, const char *ip, int port);

/** open a UDP pair that uses latency program */
void create_udp_pair(int socks[2]);
void close_udp_pair(int socks[2]);
