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
#include <getopt.h>
#include <stdbool.h>
#include <err.h>
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
usage(bool error)
{
	fprintf(error ? stderr : stdout,
		"Usage:\n"
		"\tlatency <latency> <rate> [--client <ip>] [OPTION]...\n"
		"or\n"
		"\tlatency --server [OPTION]...\n"
		"\n"
		"Options:\n"
		"  -h, --help               Show this help\n"
		"  --port <PORT>            Specify port to use (default 61234)\n"
		"  --cap-file <FN>          Specify a capture file\n"
		"  --framing-bytes <BYTES>  Specify physical framing bytes\n"
		);
	exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
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
	{ "g", 1000000000 },
	{ "G", 1024 * 1024 * 1024 },
	{ "kbit", 1000. / 8. },
	{ "Kbit", 1024. / 8. },
	{ "mbit", 1000000. / 8. },
	{ "Mbit", 1024. * 1024. / 8. },
	{ "gbit", 1000000000. / 8. },
	{ "Gbit", 1024. * 1024. * 1024./ 8. },
	{ "", 1 },
	{ NULL, 0 }
};

static const unit no_units[] = {
	{ "", 1 },
	{ NULL, 0 }
};

/**/
int
main(int argc, char **argv)
{
	uid_t ruid = getuid(), euid = geteuid();
	if (ruid != euid && euid == 0) {
		clearenv();
		setenv("HOME", "/root", 1);
		setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
		setenv("SHELL", "/bin/sh", 1);
		if (setuid(0))
			err(EXIT_FAILURE, "setuid");
	}

	enum { MODE_local, MODE_server, MODE_client } mode = MODE_local;
	enum { ARG_port = 256, ARG_client, ARG_server, ARG_capfile,
	       ARG_framingbytes };
	static struct option long_options[] = {
		{"client",  required_argument, 0,  ARG_client },
		{"server",  no_argument,       0,  ARG_server },
		{"port",    required_argument, 0,  ARG_port },
		{"cap-file",required_argument, 0,  ARG_capfile },
		{"framing-bytes",required_argument, 0,  ARG_framingbytes },
		{"help",    no_argument,       0,  'h' },
		{0,         0,                 0,  0 }
	};

	const char *str_port = "61234";
	const char *client_dest = NULL;
	int ch;
	while ((ch = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
		switch (ch) {
		case 'h':
			usage(false);
		case ARG_client:
			if (mode == MODE_server)
				usage(true);
			mode = MODE_client;
			client_dest = optarg;
			break;
		case ARG_server:
			if (mode == MODE_client)
				usage(true);
			mode = MODE_server;
			break;
		case ARG_port:
			str_port = optarg;
			break;
		case ARG_capfile:
			tun_log_filename = optarg;
			break;
		case ARG_framingbytes:
			framing_bytes = parse_value(optarg, 0, 1000, no_units);
			break;
		default:
			usage(true);
		}
	}

	tun_setup(mode == MODE_local);

	if (ruid != euid) {
		if (setuid(ruid))
			err(EXIT_FAILURE, "setuid");
	}

	int port = parse_value(str_port, 1, 65535, no_units);
	if (mode != MODE_server) {
		if (optind + 2 > argc)
			usage(true);

		latency_us = parse_value(argv[optind], 0, 10000000, latency_units);
		rate_bytes = parse_value(argv[optind+1], 1, INT_MAX, rate_units);
		if (mode == MODE_client)
			tun_set_client(client_dest, port);
	} else {
		latency_us = 0;
		rate_bytes = 100000000;
		tun_set_server(port);
	}

	setup_signals();

	handle_tun();
	return EXIT_SUCCESS;
}
