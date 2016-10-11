/* check that the delay we setup is respected */
#include "common.h"
#include "../utils.h"
#include <poll.h>

static unsigned test_num = 0;
static int udp_socks[2] = { -1, -1 };
static const char payload_id[8] = "DELAY\0\0";
static bool remote = false;

typedef struct {
	char id[8];
	unsigned test_num;
	uint64_t time;
} test_payload;

static void
wait_reply(int sock, test_payload *payload)
{
	struct pollfd fds[1];
	for (;;) {
		// wait a packet or bail out on timeout
		fds[0].fd = sock;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		int res = poll(fds, 1, 1000);
		assert(res == 1);

		// check packet received is what we expect
		if (recv(sock, payload, sizeof(*payload), MSG_TRUNC) != sizeof(*payload))
			continue;
		if (memcmp(payload->id, payload_id, sizeof(payload->id)) != 0)
			continue;
		if (payload->test_num != test_num)
			continue;

		// got it!
		return;
	}
}

static void
test_latency(unsigned latency)
{
	++test_num;
	// launch program with given latency
	if (remote)
		launch_latency_remote("%u 100M", latency);
	else
		launch_latency("%u 100M", latency);
	create_udp_pair(udp_socks);

	// send some payload and wait
	int i;
	unsigned count = 0, total_delay = 0;
	for (i = 0; i < 4; ++i) {
		uint64_t time = get_time_us();
		test_payload payload;
		memcpy(payload.id, payload_id, sizeof(payload.id));
		payload.test_num = test_num;
		payload.time = time + latency * 1000;

		send(udp_socks[i&1], &payload, sizeof(payload), MSG_NOSIGNAL);

		wait_reply(udp_socks[1 - (i&1)], &payload);

		// check the time is more or less what we expect
		time = get_time_us();
		assert(time > payload.time);
		if (time - payload.time > 4000) {
			fprintf(stderr, "Expected time %" PRIu64 " current %" PRIu64 " elapsed %" PRIu64"\n",
				payload.time, time, time - payload.time);
			exit(1);
		}
		++count;
		total_delay += (unsigned) (time - payload.time);
	}
	if (total_delay / count > 1500) {
		fprintf(stderr, "Average delay %u > 1500\n", total_delay / count);
		exit(1);
	}
	close_udp_pair(udp_socks);
	kill_latency();
}

static void
all_tests(void)
{
	test_latency(10);
	test_latency(100);
	test_latency(200);
	test_latency(280);
}

int main(void)
{
	printf("Testing delay introduced is correct\n");

	all_tests();
	remote = true;
	all_tests();

	return 0;
}
