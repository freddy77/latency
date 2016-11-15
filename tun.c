#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>

#include "tun.h"
#include "latency.h"
#include "utils.h"
#include "pcap.h"

static int tun_fd = -1;
static int tun_fd_back = -1;
static int remote_sock = -1;
static struct sockaddr_in remote_addr;
static bool remote_connected = false;
static bool is_server = false;
static pcap_file *pcap = NULL;

/* bytes for taking into account framing.
 * 14 is the usual Ethernet framing */
unsigned framing_bytes = 14;

const char *tun_log_filename = NULL;

/* Fake packets are used to send commands.
 * A fake packet has a ip header with 0 check, saddr and daddr fields
 * followed by all uint32_t fields.
 * First field is the type, defined as follow.
 */
enum {
	FAKE_settings = 1,
};
enum {
	FAKE_FIELD_type = 0,
	FAKE_FIELD_latency_us = 1,
	FAKE_FIELD_rate_bytes = 2,
};

typedef struct {
	struct iphdr iphdr;
	uint32_t fields[4];
} fake_ip_packet;

/**
 * @param dev name of interface. MUST have enough
 *        space to hold the interface name if '\0' is passed
 * @param flags interface flags (eg, IFF_TUN etc.)
 */
static int
tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return fd;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

static int
tun_init(const char *ip)
{
	char tun_name[IFNAMSIZ];
	int fd;
	char cmd[IFNAMSIZ + 128];

	tun_name[0] = 0;
	fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);
	if (fd < 0)
		err(EXIT_FAILURE, "error creating TUN device");

	sprintf(cmd, "ip link set %s up", tun_name);
	if (system(cmd) != 0)
		err(EXIT_FAILURE, "system");

	sprintf(cmd, "ip addr add %s dev %s", ip, tun_name);
	if (system(cmd) != 0)
		err(EXIT_FAILURE, "system");

	return fd;
}

void
tun_setup(bool local_mode)
{
	tun_fd = tun_init("192.168.127.0/31");

	if (local_mode)
		tun_fd_back = tun_init("192.168.127.2/31");

	setpriority(PRIO_PROCESS, 0, -20);
}

static void
create_remote_socket(void)
{
	if (tun_fd_back >= 0) {
		fprintf(stderr,	"Internal error: "
			"remote requested and local specified\n");
		exit(EXIT_FAILURE);
	}

	remote_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (remote_sock < 0)
		err(EXIT_FAILURE, "socket");
}

void
tun_set_client(const char *ip, int port)
{
	in_addr_t server_ip;

	if (port < 1 || port > 65535) {
		fprintf(stderr, "Wrong port value %d\n", port);
		exit(EXIT_FAILURE);
	}

	server_ip = inet_addr(ip);
	if (server_ip == INADDR_NONE) {
		fprintf(stderr, "Wrong ip format %s\n", ip);
		exit(EXIT_FAILURE);
	}

	create_remote_socket();

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons((short) port);
	remote_addr.sin_addr.s_addr = server_ip;

	/* initialize server */
	fake_ip_packet pkt;
	memset(&pkt, 0, sizeof(pkt));
	pkt.fields[FAKE_FIELD_type] = htonl(FAKE_settings);
	pkt.fields[FAKE_FIELD_latency_us] = htonl(latency_us);
	pkt.fields[FAKE_FIELD_rate_bytes] = htonl(rate_bytes);
	sendto(remote_sock, &pkt, sizeof(pkt), MSG_NOSIGNAL,
	       &remote_addr, sizeof(remote_addr));

	remote_connected = true;
}

void
tun_set_server(int port)
{
	if (port < 1 || port > 65535) {
		fprintf(stderr, "Wrong port value %d\n", port);
		exit(EXIT_FAILURE);
	}

	create_remote_socket();

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((short) port);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(remote_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
		err(EXIT_FAILURE, "bind");
	remote_connected = false;
	is_server = true;
}

#define MIN_PKT_LEN 2000u

static pthread_mutex_t log_mtx = PTHREAD_MUTEX_INITIALIZER;

typedef struct packet {
	struct packet *next;
	uint64_t time_to_send;
	uint16_t len;
	/* minimum MIN_PKT_LEN */
	uint8_t data[];
} packet_t;

typedef struct flow_info {
	uint64_t bytes_from_first_read;
	uint64_t first_received_at;
	int dest_fd;
	packet_t *first_packet, *last_packet;
} flow_info;

enum { PKT_DEBUG_ENABLED = 0 };

/* get packet to write to */
static packet_t *
alloc_packet(void)
{
	packet_t *pkt = malloc(sizeof(packet_t) + MIN_PKT_LEN);
	memset(pkt, 0, sizeof(*pkt));
	return pkt;
}

/* add packet to list */
static void
add_packet(flow_info *flow, packet_t *pkt)
{
	if (PKT_DEBUG_ENABLED)
		printf("added packet len %u\n", pkt->len);
	pkt = realloc(pkt, sizeof(*pkt) + pkt->len);

	if (flow->last_packet)
		flow->last_packet->next = pkt;
	else
		flow->first_packet = pkt;
	flow->last_packet = pkt;
}

static void
release_packet(packet_t *pkt)
{
	free(pkt);
}

static void
log_write_ip(const void *raw_ip, size_t len)
{
	if (!pcap)
		return;

	pthread_mutex_lock(&log_mtx);
	/* check again to avoid races */
	if (pcap)
		pcap_write_ip(pcap, raw_ip, len);
	pthread_mutex_unlock(&log_mtx);
}

/**/

static double bytes2time_ratio;

static inline int64_t
bytes2time(int64_t bytes)
{
	return bytes * bytes2time_ratio;
}

/* handke fake packets, return true if fake one */
static bool
handle_fake_packet(const uint8_t *data, size_t len)
{
	const fake_ip_packet *pkt = (const fake_ip_packet *) data;

	/* a fake packet has these 3 fields set to zeroes */
	if (pkt->iphdr.check || pkt->iphdr.saddr || pkt->iphdr.daddr)
		return false;

	const uint32_t *fields = pkt->fields;

	switch (ntohl(fields[FAKE_FIELD_type])) {
	case FAKE_settings:
		latency_us = ntohl(fields[FAKE_FIELD_latency_us]);
		rate_bytes = ntohl(fields[FAKE_FIELD_rate_bytes]);
		if (!rate_bytes)
			rate_bytes = 1;
		bytes2time_ratio = (double) 1000000.0 / rate_bytes;
		break;
	}
	return true;
}

static void*
handle_remote_flow(void *param)
{
	packet_t *pkt = alloc_packet();
	while (!term) {
		int len;
		if (!is_server) {
			len = recv(remote_sock, pkt->data, MIN_PKT_LEN, 0);
		} else {
			/* for server we record the source address to
			 * be able to send packet back */
			socklen_t sock_len = sizeof(remote_addr);
			len = recvfrom(remote_sock, pkt->data, MIN_PKT_LEN, 0,
				       &remote_addr, &sock_len);
		}
		if (len <= 0)
			break;
		remote_connected = true;
		if (len < sizeof(struct iphdr))
			continue;
		if (!handle_fake_packet(pkt->data, len)) {
			log_write_ip(pkt->data, pkt->len);
			write(tun_fd, pkt->data, len);
		}
	}
	return NULL;
}

static inline unsigned
reduce_cksum(unsigned sum)
{
	return (sum >> 16) + (sum & 0xffffu);
}

static unsigned
cksum(const void *pkt, size_t len, unsigned int start)
{
	const uint16_t *data = (const uint16_t *) pkt;
	unsigned sum = start;

	for (; len >= 2; len -= 2)
		sum += *data++;
	if (len)
		sum += ntohs(*((const uint8_t *)data) << 8);
	sum = reduce_cksum(sum);
	sum = reduce_cksum(sum);
	assert(sum < 0x10000u);
	return sum;
}

static void
nat_addresses(struct iphdr *ip)
{
	u_int32_t saddr = ip->saddr;
	if (remote_sock >= 0) {
		/* swap source and destination IPs to forward the packet
		 * coming from the real machine back to the machine again */
		ip->saddr = ip->daddr;
		ip->daddr = saddr;
		return;
	}

	/* we must do some more work for local case */
	unsigned pre = cksum(&ip->saddr, 8, 0); // 2 IPs

	if (saddr == htonl(IP(192,168,127,0))) {
		// going 127.0 -> 127.1
		ip->saddr = htonl(IP(192,168,127,3));
		ip->daddr = htonl(IP(192,168,127,2));
	} else {
		// back 127.2 -> 127.3
		ip->saddr = htonl(IP(192,168,127,1));
		ip->daddr = htonl(IP(192,168,127,0));
	}

	// adjust checksums for IP, TCP, UDP and UDP-LITE
	unsigned adjust_cksum = reduce_cksum(pre + 0xffffu - cksum(&ip->saddr, 8, 0));
	ip->check = reduce_cksum(ip->check + adjust_cksum);
	if (ip->protocol == IPPROTO_TCP) {
		uint8_t *data = (uint8_t *) ip;
		struct tcphdr *tcp = (struct tcphdr *) &data[ip->ihl*4];
		tcp->check = reduce_cksum(tcp->check + adjust_cksum);
	}
	if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_UDPLITE) {
		uint8_t *data = (uint8_t *) ip;
		struct udphdr *udp = (struct udphdr *) &data[ip->ihl*4];
		if (udp->check) {
			udp->check = reduce_cksum(udp->check + adjust_cksum);
		}
	}
}

static struct timespec*
compute_polling_timeout(flow_info *flow, struct pollfd *poll_fd, struct timespec *ts)
{
	packet_t *pkt = flow->first_packet;
	if (!pkt)
		return NULL;

	/* send expired packets */
	uint64_t curr_time = get_time_us();
	while (pkt && pkt->time_to_send <= curr_time) {
		packet_t *next = pkt->next;
		if (remote_sock >= 0) {
			if (remote_connected)
				sendto(remote_sock, pkt->data, pkt->len, MSG_NOSIGNAL,
				       &remote_addr, sizeof(remote_addr));
		} else {
			if (flow->dest_fd == tun_fd)
				log_write_ip(pkt->data, pkt->len);
			write(flow->dest_fd, pkt->data, pkt->len);
		}
		release_packet(pkt);
		pkt = next;
	}
	flow->first_packet = pkt;
	if (!pkt) {
		flow->last_packet = NULL;
		return NULL;
	}

	/* we must wakeup when we need to send a packet */
	uint64_t timeout_us = pkt->time_to_send;

	/* Do not dequeue too much packets.
	 * On a real card packets are dequeued when cable is free (actually
	 * there is a buffer in the middle). Our virtual cable is free when
	 * the last packet have to be send in a time before latency.
	 * Add an extra 5ms to account for scheduler or other delays. */
	uint64_t timeout_read_us = flow->last_packet->time_to_send - latency_us - 5 * 1000;
	if (timeout_read_us > curr_time) {
		poll_fd->fd = -1;
		if (timeout_us > timeout_read_us)
			timeout_us = timeout_read_us;
	}

	timeout_us -= curr_time;
	ts->tv_sec = timeout_us / 1000000u;
	ts->tv_nsec = (timeout_us % 1000000u) * 1000;
	return ts;
}

static void*
handle_tun_flow(void *param)
{
	int from_fd = param ? tun_fd : tun_fd_back;
	int dest_fd = param ? tun_fd_back : tun_fd;

	struct pollfd fds[1];
	fds[0].events = POLLIN;

	packet_t *pkt = alloc_packet();
	flow_info flow[1];
	memset(flow, 0, sizeof(flow));
	flow->dest_fd = dest_fd;
	while (!term) {
		struct timespec ts, *pts;
		fds[0].fd = from_fd;
		pts = compute_polling_timeout(flow, &fds[0], &ts);
		if (ppoll(fds, 1, pts, NULL) < 0) {
			if (errno != EINTR)
				break;
			continue;
		}

		if ((fds[0].revents & POLLIN) == 0)
			continue;

		int len = read(from_fd, pkt->data, MIN_PKT_LEN);

		if (len < 0)
			break;
		pkt->len = len;
		len += framing_bytes;

		if (from_fd == tun_fd)
			log_write_ip(pkt->data, pkt->len);

		struct iphdr *ip = (struct iphdr *) pkt->data;
		if (ip->version != IPVERSION)
			continue;

		uint64_t curr_time = get_time_us();

		/* Compute time to send the packet.
		 * Adjusting for latency is easy, just current time + latency.
		 * For bandwidth is a bit more complicated as we must take
		 * into account that if data flow stop after a while we must
		 * not delay next packet. Also to avoid accumulating error and
		 * assuming the source flow is quite fast we must compute from
		 * first packet we took as reference.
		 */
		uint64_t time_to_send;
		if (flow->bytes_from_first_read == 0
		    || curr_time > flow->first_received_at + bytes2time(flow->bytes_from_first_read)) {
			time_to_send = curr_time;
			flow->first_received_at = curr_time;
			flow->bytes_from_first_read = len;
		} else {
			time_to_send = flow->first_received_at + bytes2time(flow->bytes_from_first_read);
			flow->bytes_from_first_read += len;
			/* reduce values avoiding possible overflows and
			 * increasing precision (due to floating point
			 * numbers) */
			while (curr_time >= flow->first_received_at + 1000000u && flow->bytes_from_first_read > rate_bytes) {
				flow->first_received_at += 1000000u;
				flow->bytes_from_first_read -= rate_bytes;
			}
		}
		pkt->time_to_send = time_to_send + latency_us;

		nat_addresses(ip);

		add_packet(flow, pkt);
		pkt = alloc_packet();
	}
	return NULL;
}

void
handle_tun(void)
{
	pthread_t back_flow_thread;

	bytes2time_ratio = (double) 1000000.0 / rate_bytes;

	if (tun_log_filename) {
		pcap = pcap_open(tun_log_filename);
		if (!pcap)
			err(EXIT_FAILURE, "error opening log file");
	}

	if (remote_sock >= 0)
		pthread_create(&back_flow_thread, NULL, handle_remote_flow, NULL);
	else
		pthread_create(&back_flow_thread, NULL, handle_tun_flow, NULL);
	handle_tun_flow((void*) (uintptr_t) 1);

	/* close capture file */
	pthread_mutex_lock(&log_mtx);
	pcap_close(pcap);
	pcap = NULL;
	pthread_mutex_unlock(&log_mtx);
}
