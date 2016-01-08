#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "latency.h"
#include "utils.h"

static void
forward_data(int from, int to)
{
	const size_t buf_size = 1024 * 1024;
	void *buf = malloc(buf_size);
	for (;;) {
		ssize_t readed = recv(from, buf, buf_size, 0);
		if (readed <= 0)
			exit(EXIT_FAILURE);
//		usleep(latency_us);
		write_all(to, buf, readed);
	}
	free(buf);
}

static int forward_from, forward_to;
static void *
forward_thread(void *arg)
{
	forward_data(forward_from, forward_to);
	return NULL;
}

void handle_client(int fd)
{
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
