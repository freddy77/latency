#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "utils.h"

void
set_nonblocking(int sock)
{
	int on = 1;
	if (ioctl(sock, FIONBIO, &on) == -1)
		err(EXIT_FAILURE, "ioctl");
}

void
set_nodelay(int fd)
{
	int nodelay = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) == -1)
		err(EXIT_FAILURE, "ioctl");
}

void
write_all(int fd, const void *buf, size_t buf_size)
{
	const unsigned char *p = (const unsigned char *) buf;

	while (buf_size) {
		ssize_t written = write(fd, p, buf_size);
		if (written <= 0)
			exit(EXIT_FAILURE);
		buf_size -= written;
		p += written;
	}
}

int
parse_value(const char *s, int min, int max, const unit *units)
{
	char *end = NULL;
	double val;

	errno = 0;
	val = strtod(s, &end);
	if (errno != 0) {
		fprintf(stderr, "Invalid value %s\n", s);
		exit(EXIT_FAILURE);
	}

	if (end == s) {
		fprintf(stderr, "No digit in %s\n", s);
		exit(EXIT_FAILURE);
	}

	for (; units->suffix; ++units) {
		if (strcmp(end, units->suffix) != 0)
			continue;
		val *= units->scale;
		if (val < min || val > max) {
			fprintf(stderr, "Value %s out of range [%d-%d]\n", s, min, max);
			exit(EXIT_FAILURE);
		}
		return (int) val;
	}
	fprintf(stderr, "Wrong format %s\n", s);
	exit(EXIT_FAILURE);
}
