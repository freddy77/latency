#include "common.h"
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>

static pid_t latency_pid = -1;

bool
latency_running(void)
{
	int socktrue = 1;
	sockaddr_all addr;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &socktrue, sizeof(socktrue));
	setup_addr(&addr, "192.168.127.0", 0);
	bool res;
	if (bind(sock, &addr.generic, sizeof(addr)) == 0) {
		res = true;
	} else {
		assert(errno == EADDRNOTAVAIL);
		res = false;
	}
	close(sock);
	return res;
}

void
launch_latency(const char *fmt, ...)
{
	assert(latency_pid == -1);

	while (latency_running()) {
		system("killall latency > /dev/null 2> /dev/null");
		usleep(2000);
	}

	char cmd[1024];
	va_list ap;

	strcpy(cmd, "exec ../latency ");
	size_t cmd_len = strlen(cmd);

	va_start(ap, fmt);
	vsnprintf(cmd + cmd_len, sizeof(cmd) - cmd_len, fmt, ap);
	va_end(ap);

	printf("starting %s\n", cmd);
	latency_pid = fork();
	assert(latency_pid != -1);

	if (latency_pid == 0) {
		execlp("sh", "sh", "-c", cmd, NULL);
		kill(getpid(), SIGKILL);
		exit(1);
	}

	int count;
	while (!latency_running()) {
		usleep(2000);
		assert(++count < 100);
	}
	usleep(50000);
}

static void
handle_alarm(int sig)
{
}

void
kill_latency(void)
{
	assert(latency_pid != -1);
	kill(latency_pid, SIGTERM);

	// handle some timeout
	signal(SIGALRM, handle_alarm);
	alarm(1);

	int status;
	pid_t pid = waitpid(latency_pid, &status, 0);
	alarm(0);
	signal(SIGALRM, SIG_DFL);

	assert(pid == latency_pid);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);

	latency_pid = -1;
}

void
setup_addr(sockaddr_all *addr, const char *ip, int port)
{
	struct in_addr inet;
	assert(inet_aton(ip, &inet) == 1);

	addr->inet.sin_family = AF_INET;
	addr->inet.sin_addr = inet;
	addr->inet.sin_port = htons(port);
}

void
create_udp_pair(int socks[2])
{
	int sock;
	int socktrue = 1;
	sockaddr_all addr;
	socklen_t addr_len;
	int ports[2];

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	socks[0] = sock;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &socktrue, sizeof(socktrue));
	setup_addr(&addr, "192.168.127.0", 0);
	assert(bind(sock, &addr.generic, sizeof(addr)) == 0);
	addr_len = sizeof(addr);
	assert(getsockname(sock, &addr.generic, &addr_len) == 0);
	ports[0] = ntohs(addr.inet.sin_port);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	socks[1] = sock;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &socktrue, sizeof(socktrue));
	setup_addr(&addr, "192.168.127.0", 0);
	assert(bind(sock, &addr.generic, sizeof(addr)) == 0);
	addr_len = sizeof(addr);
	assert(getsockname(sock, &addr.generic, &addr_len) == 0);
	ports[1] = ntohs(addr.inet.sin_port);

	// make a pair from the above ones
	setup_addr(&addr, "192.168.127.1", ports[1]);
	assert(connect(socks[0], &addr.generic, sizeof(addr)) == 0);
	setup_addr(&addr, "192.168.127.1", ports[0]);
	assert(connect(socks[1], &addr.generic, sizeof(addr)) == 0);
}

void
close_udp_pair(int socks[2])
{
	close(socks[0]);
	close(socks[1]);
	socks[0] = socks[1] = -1;
}
