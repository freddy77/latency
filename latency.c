/* Attempt to reduce bandwidth of a given connection
 *
 * args:
 * - listening port;
 * - connection port;
 * - latency (ms);
 * - bandwidth kbits (send/receive or receive);
 * - bandwidth kbits (send).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "latency.h"
#include "utils.h"

volatile int term = 0;

static void
sig_term(int sig)
{
	term = 1;
}

static void
sig_chld(int sig)
{
	int status;

	while (waitpid(-1, &status, WNOHANG) > 0)
		continue;
}

static void
setup_signals(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	signal(SIGCHLD, sig_chld);
}

int connect_port;
uint64_t latency_us;
unsigned rate_bytes;

static void
usage(void)
{
	fprintf(stderr, "syntax: latency <listen_port> <connect_port> <latency> <rate>\n");
	exit(EXIT_FAILURE);
}

static const unit latency_units[] = {
	{ "ms", 1000 },
	{ "s", 1000000 },
	{ "", 1000 },
	{ NULL, 0 }
};

static const unit rate_units[] = {
	{ "k", 1000 },
	{ "K", 1024 },
	{ "m", 1000000 },
	{ "M", 1024 * 1024 },
	{ "kbit", 1000. / 8. },
	{ "Kbit", 1024. / 8. },
	{ "mbit", 1000000. / 8. },
	{ "Mbit", 1024. * 1024. / 8. },
	{ "", 1 },
	{ NULL, 0 }
};

/**/
int
main(int argc, char **argv)
{
	if (argc < 5)
		usage();

	int listen_port = atoi(argv[1]);
	connect_port = atoi(argv[2]);
	latency_us = parse_value(argv[3], 0, 10000000, latency_units);
	rate_bytes = parse_value(argv[4], 1, INT_MAX, rate_units);

	if (listen_port <= 0 || connect_port <= 0
	    || listen_port > 0xffff || connect_port > 0xffff
	    || listen_port == connect_port)
		usage();

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	int on = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(listen_port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (listen(sock, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	setup_signals();

	unsigned connection_id = 0;
	while (!term) {
		int fd = accept(sock, NULL, NULL);
		if (fd == -1) {
			if (term)
				break;
			perror("accept");
			continue;
		}

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		switch (fork()) {
		case -1:
			perror("fork");
			close(fd);
			break;
		case 0:
			/* child */
			close(sock);
			signal(SIGTERM, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			handle_client(fd, ++connection_id);
			exit(EXIT_SUCCESS);
			break;
		default:
			/* parent */
			close(fd);
			break;
		}
	}
	return EXIT_SUCCESS;
}
