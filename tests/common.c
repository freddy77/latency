#include "common.h"
#include <stdarg.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static pid_t latency_pid = -1;
static pid_t server_pid = -1;
static bool cleanup_registered = false;

static void
cleanup_atexit(void)
{
	if (latency_pid != -1)
		kill(SIGKILL, latency_pid);
	if (server_pid != -1)
		kill(SIGKILL, server_pid);
}

static void
register_cleanup(void)
{
	if (cleanup_registered)
		return;
	atexit(cleanup_atexit);
	cleanup_registered = true;
}

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

static int
get_process_netns(pid_t pid)
{
	char ns_path[128];
	sprintf(ns_path, "/proc/%u/ns/net", (unsigned) pid);
	int ns = open(ns_path, O_RDONLY);
	assert(ns >= 0);
	return ns;
}

static void
launch_latency_client(bool local, const char *fmt, va_list ap)
{
	register_cleanup();
	assert(latency_pid == -1);

	while (latency_running()) {
		system("killall latency > /dev/null 2> /dev/null");
		usleep(2000);
	}

	char cmd[1024];

	if (local)
		strcpy(cmd, "exec ../latency ");
	else
		strcpy(cmd, "exec ../latency --client 192.168.128.2 ");
	size_t cmd_len = strlen(cmd);

	vsnprintf(cmd + cmd_len, sizeof(cmd) - cmd_len, fmt, ap);

	printf("starting %s\n", cmd);
	latency_pid = fork();
	assert(latency_pid != -1);

	if (latency_pid == 0) {
		execlp("sh", "sh", "-c", cmd, NULL);
		kill(getpid(), SIGKILL);
		exit(1);
	}

	int count = 0;
	while (!latency_running()) {
		usleep(2000);
		assert(++count < 100);
	}
	usleep(50000);
}

void
launch_latency(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	launch_latency_client(true, fmt, ap);
	va_end(ap);
}

void
launch_latency_remote(const char *fmt, ...)
{
	register_cleanup();
	assert(latency_pid == -1 && server_pid == -1);

	if (unshare(CLONE_NEWNET))
		err(1, "unshare");
	assert(system("ifconfig lo 127.0.0.1 netmask 255.255.255.0 up") == 0);

	int pipe_fds[2];

	assert(pipe(pipe_fds) == 0);

	server_pid = fork();
	assert(server_pid != -1);

	char c;
	if (server_pid == 0) {
		char cmd[256];

		close(pipe_fds[0]);
		pipe_fds[0] = -1;

		if (unshare(CLONE_NEWNET))
			err(1, "unshare");
		assert(system("ifconfig lo 127.0.0.1 netmask 255.255.255.0 up") == 0);
		sprintf(cmd, "ip link add server type veth peer name client netns %d", (int) getppid());
		assert(system(cmd) == 0);
		assert(system("ifconfig server 192.168.128.2 netmask 255.255.255.0 up") == 0);
		c = 'x';
		write(pipe_fds[1], &c, 1);
		close(pipe_fds[1]);
		execl("../latency", "latency", "--server", "--framing-bytes", "0", NULL);
		exit(1);
	}

	close(pipe_fds[1]);
	pipe_fds[1] = -1;
	assert(read(pipe_fds[0], &c, 1) == 1);
	assert(c == 'x');
	assert(system("ifconfig client 192.168.128.3 netmask 255.255.255.0 up") == 0);

	va_list ap;
	va_start(ap, fmt);
	launch_latency_client(false, fmt, ap);
	va_end(ap);
}

static void
handle_alarm(int sig)
{
}

static void
kill_pid(pid_t *p_pid)
{
	assert(*p_pid != -1);
	kill(*p_pid, SIGTERM);

	// handle some timeout
	signal(SIGALRM, handle_alarm);
	alarm(1);

	int status;
	pid_t pid = waitpid(*p_pid, &status, 0);
	alarm(0);
	signal(SIGALRM, SIG_DFL);

	assert(pid == *p_pid);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);

	*p_pid = -1;
}

void
kill_latency(void)
{
	kill_pid(&latency_pid);
	if (server_pid != -1) {
		kill_pid(&server_pid);

		int parent_ns = get_process_netns(getppid());
		assert(setns(parent_ns, 0) == 0);
		close(parent_ns);
	}
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

	const char *remote_listen_ip = "192.168.127.2";
	const char *remote_connect_ip = "192.168.127.3";

	int save_ns = -1;
	if (server_pid != -1) {
		save_ns = get_process_netns(getpid());

		int server_ns = get_process_netns(server_pid);
		assert(setns(server_ns, 0) == 0);
		close(server_ns);

		remote_listen_ip = "192.168.127.0";
		remote_connect_ip = "192.168.127.1";
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	socks[1] = sock;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &socktrue, sizeof(socktrue));
	setup_addr(&addr, remote_listen_ip, 0);
	assert(bind(sock, &addr.generic, sizeof(addr)) == 0);
	addr_len = sizeof(addr);
	assert(getsockname(sock, &addr.generic, &addr_len) == 0);
	ports[1] = ntohs(addr.inet.sin_port);

	if (save_ns != -1) {
		assert(setns(save_ns, 0) == 0);
		close(save_ns);
	}

	// make a pair from the above ones
	setup_addr(&addr, "192.168.127.1", ports[1]);
	assert(connect(socks[0], &addr.generic, sizeof(addr)) == 0);
	setup_addr(&addr, remote_connect_ip, ports[0]);
	assert(connect(socks[1], &addr.generic, sizeof(addr)) == 0);
}

void
close_udp_pair(int socks[2])
{
	close(socks[0]);
	close(socks[1]);
	socks[0] = socks[1] = -1;
}
