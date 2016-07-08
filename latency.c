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
#include "tun.h"
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

uint64_t latency_us;
unsigned rate_bytes;

static void
usage(void)
{
	fprintf(stderr, "syntax: latency <latency> <rate>\n");
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
	tun_fd = tun_setup();

	if (argc < 3)
		usage();

	latency_us = parse_value(argv[1], 0, 10000000, latency_units);
	rate_bytes = parse_value(argv[2], 1, INT_MAX, rate_units);

	setup_signals();

	handle_tun(tun_fd);
	return EXIT_SUCCESS;
}
