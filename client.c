#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <assert.h>

#include "latency.h"
#include "utils.h"

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

static void
forward_data(int from, int to)
{
	const size_t max_buf_size = 1024 * 1024;
	void *buf = malloc(max_buf_size);
	size_t buf_size = 0;

	typedef struct {
		uint64_t received_at;
		unsigned size;
	} chunk;

	const unsigned max_chunks = 128;
	chunk chunks[max_chunks];

	uint64_t curr_time;
	uint64_t bytes_from_first_read = 0;

	struct pollfd pollfds[1] = {
		{ -1, POLLIN, 0 },
	};

	chunk *curr_chunk = &chunks[0];
	curr_chunk->received_at = 0;
	curr_chunk->size = 0;

	for (;;) {
		/* wait for some events */
		int timeout = -1;
		bool got_timeout = false;
		pollfds[0].fd = buf_size < max_buf_size && curr_chunk - chunks < max_chunks - 1 ? from : -1;

		if (buf_size) {
			/* compute time to wait first time */
			uint64_t to_wait = chunks[0].received_at + latency_us + bytes2time(bytes_from_first_read);
			curr_time = get_time_us();
			if (to_wait > curr_time)
				timeout = (to_wait - curr_time) / 1000u;
			timeout = MAX(timeout, 1);
		}

		switch (poll(pollfds, 1, timeout)) {
		case -1:
			perror("poll");
			exit(EXIT_FAILURE);
		case 0:
			got_timeout = true;
			break;
		}

		if (pollfds[0].fd >= 0 && pollfds[0].revents) {
			/* compute time we receive first data */
			uint64_t new_first_read = get_time_us();
			if (!curr_chunk->size) {
				/* new start point */
				assert(curr_chunk == &chunks[0]);
				curr_chunk->received_at = new_first_read;
				bytes_from_first_read = 0;
			} else {
				assert(new_first_read > curr_chunk->received_at);
				// XXX constant for time, consider possible latency from read
				// compute how much bytes we should have send in this time
				if (curr_chunk->received_at + latency_us + bytes2time(curr_chunk == chunks ? bytes_from_first_read : curr_chunk->size) + 2000u < new_first_read) {
					DEBUG("updated\n");
					++curr_chunk;
					curr_chunk->received_at = new_first_read;
					curr_chunk->size = 0;
				} else {
					/* reduce values avoiding possible overflows */
					while (new_first_read >= chunks[0].received_at + 1000000u && bytes_from_first_read >= rate_bytes) {
						chunks[0].received_at += 1000000u;
						bytes_from_first_read -= rate_bytes;
					}
				}
			}

			assert(buf_size >= 0 && buf_size < max_buf_size);
			ssize_t len = recv(from, buf + buf_size, max_buf_size - buf_size, 0);
			if (len <= 0)
				exit(EXIT_FAILURE);
			buf_size += len;
			curr_chunk->size += len;
			assert(buf_size > 0 && buf_size <= max_buf_size);
		}

		if (got_timeout) {
			// compute bytes we can write
			curr_time = get_time_us();
			int64_t bytes = time2bytes(curr_time - chunks[0].received_at - latency_us) - bytes_from_first_read;
			if (bytes > 0) {
				assert(chunks[0].size > 0);
				bytes = MIN(bytes, chunks[0].size);
				write_all(to, buf, bytes);
				buf_size -= bytes;
				memmove(buf, buf + bytes, buf_size);
				chunks[0].size -= bytes;
				bytes_from_first_read += bytes;
				/* go to next chunk */
				if (chunks[0].size == 0 && curr_chunk != chunks) {
					memmove(&chunks[0], &chunks[1], (char*) curr_chunk - (char*) &chunks[0]);
					--curr_chunk;
					bytes_from_first_read = 0;
				}
			}
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
