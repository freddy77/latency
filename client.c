#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <assert.h>

#include "latency.h"
#include "utils.h"

static bool wait_input(int fd, int timeout);
static inline uint64_t get_time_us(void);

static unsigned curr_connection_id;
static __thread char direction = '>';

#define DEBUG(fmt, ...) printf("%u%c: " fmt, curr_connection_id, direction, ## __VA_ARGS__)

static inline int64_t
time2bytes(int64_t time_us)
{
	return time_us * rate_bytes / 1000000u;
}

static inline int64_t
bytes2time(int64_t bytes)
{
	return bytes * 1000000u / rate_bytes;
}

static bool
wait_input(int fd, int timeout)
{
	struct pollfd pollfd = { fd, POLLIN, 0 };
	switch (poll(&pollfd, 1, timeout)) {
	case -1:
		perror("poll");
		exit(EXIT_FAILURE);
	case 0:
		/* timeout */
		return false;
	}
	DEBUG("got data\n");
	return true;
}

static ssize_t
read_all(int fd, void *buf, size_t buf_size)
{
	unsigned char *p = (unsigned char *) buf;
	ssize_t readed = 0;
	for (;;) {
		if (!wait_input(fd, 0) && readed)
			break;

		ssize_t len = recv(fd, p, buf_size, 0);
		if (len == 0)
			break;
		if (len < 0) {
			if (readed)
				break;
			return len;
		}
		readed += len;
		buf_size -= len;
		p += len;
	}
	return readed;
}

static void
forward_data(int from, int to)
{
	const size_t buf_size = 1024 * 1024;
	void *buf = malloc(buf_size);

	uint64_t curr_time;
	uint64_t last_first_read = 0;
	uint64_t bytes_from_first_read = 0;

	for (;;) {
		/* compute time we receive first data */
		wait_input(from, -1);
		uint64_t new_first_read = get_time_us();
		if (!last_first_read) {
			/* new start point */
			last_first_read = new_first_read;
			bytes_from_first_read = 0;
		} else {
			assert(new_first_read > last_first_read);
			// XXX constant for time, consider possible latency from read
			// compute how much bytes we should have send in this time
			if (last_first_read + latency_us + bytes2time(bytes_from_first_read) + 2000u < new_first_read) {
				DEBUG("updated\n");
				last_first_read = new_first_read;
				bytes_from_first_read = 0;
			} else {
				DEBUG("not updated\n");
				while (new_first_read >= last_first_read + 1000000u && bytes_from_first_read >= rate_bytes) {
					last_first_read += 1000000u;
					bytes_from_first_read -= rate_bytes;
				}
			}
		}

		/* read as much data as available */
		/* here the buffer is empty so we must consider first time we have data */
		ssize_t readed = read_all(from, buf, buf_size);
		if (readed <= 0)
			exit(EXIT_FAILURE);

		/* compute time to wait first time */
		uint64_t to_wait = latency_us + bytes2time(bytes_from_first_read);
		curr_time = get_time_us();
		if (to_wait > curr_time && to_wait - curr_time > 1000)
			usleep(to_wait - curr_time);
		size_t written = 0;
		for (;;) {
			// compute bytes we can read
			curr_time = get_time_us();
			int64_t bytes = time2bytes(curr_time - last_first_read - latency_us) - bytes_from_first_read;
			if (bytes > 0) {
				bytes = MIN(bytes, readed - written);
				write_all(to, buf + written, bytes);
				written += bytes;
				bytes_from_first_read += bytes;
				if (written >= readed)
					break;
			}
			usleep(1000);
		}
	}
	free(buf);
}

static int forward_from, forward_to;
static void *
forward_thread(void *arg)
{
	direction = '<';
	forward_data(forward_from, forward_to);
	return NULL;
}

void handle_client(int fd, unsigned connection_id)
{
	curr_connection_id = connection_id;

	set_nodelay(fd);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(connect_port);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	set_nodelay(sock);

	/* here we use a thread to close all connections if any error */
	pthread_t th;
	forward_from = fd;
	forward_to = sock;
	if (pthread_create(&th, NULL, forward_thread, NULL)) {
		perror("pthread_create");
		exit(EXIT_FAILURE);
	}
	forward_data(sock, fd);
}
