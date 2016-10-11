/* check that ping is working */
#include "common.h"

int main(void)
{
	printf("Testing ping is working\n");

	launch_latency("10 100M");
	assert(system("ping -c1 192.168.127.1") == 0);
	kill_latency();

	launch_latency_remote("10 100M");
	assert(system("ping -c1 192.168.127.1") == 0);
	kill_latency();
	return 0;
}
