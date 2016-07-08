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
#define MIN_LEN (MIN_PKT_LEN + sizeof(packet_t))
#define PKT_BUF_LEN (1024u * 1024u * 4u)
#define ROUND_UP(n, m) (((n) + ((m) - 1)) & -(m))

static pthread_mutex_t pkt_buf_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pkt_cond_write = PTHREAD_COND_INITIALIZER;
static pthread_cond_t pkt_cond_read  = PTHREAD_COND_INITIALIZER;
/* buffer is either
 * 0    head    tail    end
 * (size = tail - head)
 * or
 * 0    tail    head    end
 * (size = PKT_BUF_LEN - (head - tail = PKT_BUF_LEN + tail - head)
 */
static uint8_t pkt_buf[PKT_BUF_LEN];
/* allocate from tail, read from head */
static uint32_t pkt_head, pkt_tail;

typedef struct {
	uint64_t time_to_send;
	uint16_t len;
	/* minimum MIN_PKT_LEN */
	uint8_t data[];
} packet_t;

static inline uint32_t
buf_allocated(void)
{
	return pkt_tail >= pkt_head ? pkt_tail - pkt_head : PKT_BUF_LEN + pkt_tail - pkt_head;
}

#define PKT_DEBUG do { \
	printf("%s:%d: head %u tail %u\n", __func__, __LINE__, pkt_head, pkt_tail); \
} while(0)
#define PKT_DEBUG_OUT do { \
	printf("%s:%d: head %u tail %u -> %u\n", __func__, __LINE__, pkt_head, pkt_tail, (unsigned) ((uint8_t *) pkt - pkt_buf)); \
} while(0)

/* get packet to write to */
static packet_t *
alloc_packet(void)
{
	PKT_DEBUG;

	packet_t *pkt;

	pthread_mutex_lock(&pkt_buf_mtx);
	while (buf_allocated() > PKT_BUF_LEN - 2 * MIN_LEN)
		pthread_cond_wait(&pkt_cond_read, &pkt_buf_mtx);
	if (pkt_tail >= pkt_head && PKT_BUF_LEN - pkt_tail < MIN_LEN)
		pkt_tail = 0;
	pkt = (packet_t *) (pkt_buf + pkt_tail);
	pthread_mutex_unlock(&pkt_buf_mtx);
	PKT_DEBUG_OUT;
	return pkt;
}

/* add packet to list */
static void
add_packet(packet_t *pkt)
{
	PKT_DEBUG;
	printf("added packet len %u\n", pkt->len);

	pthread_mutex_lock(&pkt_buf_mtx);
	pkt_tail += ROUND_UP(sizeof(packet_t) + pkt->len, 16);
	pthread_cond_signal(&pkt_cond_write);
	pthread_mutex_unlock(&pkt_buf_mtx);
	PKT_DEBUG;
}

static packet_t *
get_packet(void)
{
	PKT_DEBUG;

	packet_t *pkt;

	pthread_mutex_lock(&pkt_buf_mtx);
	while (buf_allocated() == 0)
		pthread_cond_wait(&pkt_cond_write, &pkt_buf_mtx);
	pkt = (packet_t *) (pkt_buf + pkt_head);
	pthread_mutex_unlock(&pkt_buf_mtx);
	PKT_DEBUG_OUT;
	return pkt;
}

static void
release_packet(packet_t *pkt)
{
	PKT_DEBUG;

	pthread_mutex_lock(&pkt_buf_mtx);
	pkt_head += ROUND_UP(sizeof(packet_t) + pkt->len, 16);
	if (pkt_head >= pkt_tail && PKT_BUF_LEN - pkt_head < MIN_LEN)
		pkt_head = 0;
	pthread_cond_signal(&pkt_cond_read);
	pthread_mutex_unlock(&pkt_buf_mtx);
	PKT_DEBUG;
}

static void* writer_proc(void *ptr)
{
	packet_t *pkt;

	while ((pkt = get_packet())) {
		write(tun_fd, pkt->data, pkt->len);
		release_packet(pkt);
	}
	return NULL;
}

/**/

void
handle_tun(int fd)
{
	packet_t *pkt;
	pthread_t writer;

	pthread_create(&writer, NULL, writer_proc, NULL);

	while ((pkt = alloc_packet())) {
		int len = read(fd, pkt->data, MIN_PKT_LEN);
		if (len < 0)
			break;

		pkt->len = len;
		struct iphdr *ip = (struct iphdr *) pkt->data;
		u_int32_t addr = ip->saddr;
		ip->saddr = ip->daddr;
		ip->daddr = addr;

		add_packet(pkt);
	}
}
