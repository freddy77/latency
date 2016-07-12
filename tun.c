#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "tun.h"
#include "latency.h"
#include "utils.h"

int tun_fd = -1;

/**
 * @param dev name of interface. MUST have enough
 *        space to hold the interface name if '\0' is passed
 * @param flags interface flags (eg, IFF_TUN etc.)
 */
static int tun_alloc(char *dev, int flags)
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

int tun_setup(void)
{
	char tun_name[IFNAMSIZ];
	int fd;
	char cmd[IFNAMSIZ + 128];

	tun_name[0] = 0;
	fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);
	if (fd < 0) {
		perror("error creating TUN device");
		exit(EXIT_FAILURE);
	}

	sprintf(cmd, "ip link set %s up", tun_name);
	if (system(cmd) != 0) {
		perror("system");
		exit(EXIT_FAILURE);
	}

	sprintf(cmd, "ip addr add 192.168.127.0/30 dev %s", tun_name);
	if (system(cmd) != 0) {
		perror("system");
		exit(EXIT_FAILURE);
	}

	return fd;
}

#define MIN_PKT_LEN 2000u
#define PKT_BUF_LEN (1024u * 1024u * 32u)
#define NUM_FLOWS 2

static pthread_mutex_t pkt_buf_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pkt_cond_write = PTHREAD_COND_INITIALIZER;
static pthread_cond_t pkt_cond_read  = PTHREAD_COND_INITIALIZER;

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
	packet_t *first_packet, *last_packet;
} flow_info;

static flow_info flows[NUM_FLOWS];
static uint32_t bytes_queued = 0;

static inline uint32_t
buf_allocated(void)
{
	return bytes_queued;
}

enum { PKT_DEBUG_ENABLED = 0 };

/* get packet to write to */
static packet_t *
alloc_packet(void)
{
	pthread_mutex_lock(&pkt_buf_mtx);
	while (buf_allocated() > PKT_BUF_LEN - MIN_PKT_LEN)
		pthread_cond_wait(&pkt_cond_read, &pkt_buf_mtx);
	pthread_mutex_unlock(&pkt_buf_mtx);

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

	pthread_mutex_lock(&pkt_buf_mtx);
	bytes_queued += pkt->len;
	if (flow->last_packet)
		flow->last_packet->next = pkt;
	else
		flow->first_packet = pkt;
	flow->last_packet = pkt;
	pthread_cond_signal(&pkt_cond_write);
	pthread_mutex_unlock(&pkt_buf_mtx);
}

static packet_t *
get_packet(void)
{
	flow_info *min_flow;
	unsigned n;

	pthread_mutex_lock(&pkt_buf_mtx);
	while (buf_allocated() == 0)
		pthread_cond_wait(&pkt_cond_write, &pkt_buf_mtx);

	min_flow = NULL;
	for (n = 0; n < NUM_FLOWS; ++n) {
		flow_info *flow = &flows[n];
		if (!flow->first_packet)
			continue;
		if (!min_flow) {
			min_flow = flow;
			continue;
		}
		if (flow->first_packet->time_to_send < min_flow->first_packet->time_to_send)
			min_flow = flow;
	}

	packet_t *pkt = min_flow->first_packet;
	min_flow->first_packet = pkt->next;
	if (!min_flow->first_packet)
		min_flow->last_packet = NULL;

	pthread_mutex_unlock(&pkt_buf_mtx);
	pkt->next = NULL;
	return pkt;
}

static void
release_packet(packet_t *pkt)
{
	pthread_mutex_lock(&pkt_buf_mtx);
	bytes_queued -= pkt->len;
	pthread_cond_signal(&pkt_cond_read);
	pthread_mutex_unlock(&pkt_buf_mtx);
	free(pkt);
}

static void* writer_proc(void *ptr)
{
	packet_t *pkt;

	while ((pkt = get_packet())) {
		uint64_t curr_time = get_time_us();
		if (pkt->time_to_send > curr_time)
			usleep(pkt->time_to_send - curr_time);
		write(tun_fd, pkt->data, pkt->len);
		release_packet(pkt);
	}
	return NULL;
}

/**/

static double bytes2time_ratio;

static inline int64_t
bytes2time(int64_t bytes)
{
	return bytes * bytes2time_ratio;
}

void
handle_tun(int fd)
{
	packet_t *pkt;
	pthread_t writer;
	flow_info *flow;

	memset(&flows, 0, sizeof(flows));

	bytes2time_ratio = (double) 1000000.0 / rate_bytes;

	pthread_create(&writer, NULL, writer_proc, NULL);

	uint64_t old_time = get_time_us();
	uint64_t tot_bytes = 0;
	uint32_t num_packets = 0;

	while (!term && (pkt = alloc_packet())) {
		int len = read(fd, pkt->data, MIN_PKT_LEN);
		if (len < 0)
			break;

		struct iphdr *ip = (struct iphdr *) pkt->data;
		if (ip->version != IPVERSION)
			continue;
		flow = &flows[ip->daddr == htonl(0xc0a87f00)];

		uint64_t curr_time = get_time_us();
		uint64_t time_to_send;

		tot_bytes += len;
		num_packets++;
		if (old_time + 1000000u <= curr_time) {
			printf("bytes/s %g\n", (double) tot_bytes * 1000000.0 / (curr_time - old_time));
			printf("%u packets (avg %u)\n", num_packets, num_packets ? (unsigned) (tot_bytes / num_packets) : 0u);
			old_time = curr_time;
			tot_bytes = 0;
			num_packets = 0;
		}

		pkt->len = len;
		if (flow->bytes_from_first_read == 0
		    || curr_time > flow->first_received_at + bytes2time(flow->bytes_from_first_read)) {
			time_to_send = curr_time;
			flow->first_received_at = curr_time;
			flow->bytes_from_first_read = len;
		} else {
			time_to_send = flow->first_received_at + bytes2time(flow->bytes_from_first_read);
			flow->bytes_from_first_read += len;
			/* reduce values avoiding possible overflows */
			while (curr_time >= flow->first_received_at + 1000000u && flow->bytes_from_first_read >= rate_bytes) {
				flow->first_received_at += 1000000u;
				flow->bytes_from_first_read -= rate_bytes;
			}
		}
		pkt->time_to_send = time_to_send + latency_us;
		u_int32_t addr = ip->saddr;
		ip->saddr = ip->daddr;
		ip->daddr = addr;

		add_packet(flow, pkt);
	}
}
