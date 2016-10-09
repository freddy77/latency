/* Check bandwidth set is respected.
 * This tests uses UDP packets as they not depend on window or
 * other TCP synchronizations and also is easier to compute
 * bandwidth as header is simpler.
 */
#include "common.h"
#include "../utils.h"
#include <poll.h>
#include <pthread.h>

#define MIN_IP_UDP_HEADER 28

static unsigned current_bw = 0;
static int udp_socks[2] = { -1, -1 };

typedef struct {
	uint8_t data[1024];
} test_payload;

#define SOCK2PTR(s) ((void *)(uintptr_t)(s))
#define PTR2SOCK(p) ((int)(uintptr_t)(p))

static void *
send_proc(void *arg)
{
	int sock = PTR2SOCK(arg);
	test_payload payload;

	int n;
	for (n = 0; n < sizeof(payload.data); ++n)
		payload.data[n] = n * 123 + 456;

	uint64_t start_time = get_time_us();
	while (get_time_us() - start_time < 130 * 1000) {
		for (n = current_bw / 4; n >= 0; --n)
			send(sock, &payload, sizeof(payload), MSG_NOSIGNAL);
		usleep(1000);
	}
	return NULL;
}

static void *
recv_proc(void *arg)
{
	int sock = PTR2SOCK(arg);
	test_payload payload;

	uint64_t bytes_received = 0;
	uint64_t start_time = 0;
	for (;;) {
		ssize_t len = recv(sock, &payload, sizeof(payload), MSG_TRUNC);
		assert(len > 0);

		uint64_t curr_time = get_time_us();
		assert(bytes_received <= 0xffffffffu - len - MIN_IP_UDP_HEADER);
		if (start_time == 0)
			start_time = curr_time;
		else
			bytes_received += len + MIN_IP_UDP_HEADER;
		if (curr_time - start_time >= 100 * 1000)
			break;
	}
	return (void *) (uintptr_t) bytes_received;
}

static void
flush_socks(void)
{
	struct pollfd fds[2];
	int i;

	fds[0].fd = udp_socks[0];
	fds[0].events = POLLIN;
	fds[1].fd = udp_socks[1];
	fds[1].events = POLLIN;
	for (;;) {
		// wait any packet for 30 ms
		fds[0].revents = 0;
		fds[1].revents = 0;
		int res = poll(fds, 2, 30);
		if (res == 0)
			break;

		for (i = 0; i < 2; ++i) {
			char buf[1024];
			if (fds[i].revents)
				recv(fds[i].fd, buf, sizeof(buf), MSG_TRUNC);
		}
	}
}

static void
check_res(pthread_t th, unsigned expected)
{
	void *thread_res;
	assert(pthread_join(th, &thread_res) == 0);

	unsigned bytes_received = (uintptr_t) thread_res;

	printf("received %u/%u\n", bytes_received, expected);
	// check into -5% to +5%
	assert(bytes_received >= expected * 0.96 && bytes_received <= expected * 1.04);
}

static void
test_bandwidth(unsigned bw)
{
	current_bw = bw;

	pthread_t th[3];
	unsigned expected = 1024 * 1024 * bw / 8 / 10 + 1 * (1024 + MIN_IP_UDP_HEADER);

	// launch program with given latency
	launch_latency("10 %uMbit", bw);
	create_udp_pair(udp_socks);

	// one direction
	assert(pthread_create(th, NULL, recv_proc, SOCK2PTR(udp_socks[1])) == 0);
	send_proc(SOCK2PTR(udp_socks[0]));
	check_res(th[0], expected);

	// other direction
	flush_socks();
	assert(pthread_create(th, NULL, recv_proc, SOCK2PTR(udp_socks[0])) == 0);
	send_proc(SOCK2PTR(udp_socks[1]));
	check_res(th[0], expected);

	close_udp_pair(udp_socks);
	kill_latency();
}

int main(void)
{
	printf("Testing bandwidth limitation\n");

	test_bandwidth(2);
	test_bandwidth(4);
	test_bandwidth(8);
	test_bandwidth(16);
	return 0;
}
