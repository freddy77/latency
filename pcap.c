#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

#include "pcap.h"

#define LINKTYPE_RAW	101

typedef struct {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr;

typedef struct {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr;

struct pcap_file {
	FILE *f;
	char buf[1024 * 16];
};

pcap_file *
pcap_open(const char *fn)
{
	pcap_file *pcap = (pcap_file *) malloc(sizeof(*pcap));
	if (!pcap)
		return NULL;

	FILE *f;
	pcap->f = f = fopen(fn, "wb");
	if (!f) {
		free(pcap);
		return NULL;
	}

	setvbuf(f, pcap->buf, _IOFBF, sizeof(pcap->buf));

	pcap_hdr hdr;
	hdr.magic_number = 0xa1b2c3d4;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535;
	hdr.network = LINKTYPE_RAW;

	if (fwrite(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
		fclose(f);
		unlink(fn);
		free(pcap);
		return NULL;
	}

	return pcap;
}

void
pcap_close(pcap_file *pcap)
{
	if (pcap) {
		fclose(pcap->f);
		free(pcap);
	}
}

bool
pcap_write_ip(pcap_file *pcap,
	      const void *raw_ip, size_t len)
{
	assert(pcap);

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	pcaprec_hdr hdr;
	hdr.ts_sec = ts.tv_sec;
	hdr.ts_usec = ts.tv_nsec / 1000;
	hdr.incl_len = len;
	hdr.orig_len = len;

	if (fwrite(&hdr, 1, sizeof(hdr), pcap->f) != sizeof(hdr))
		return false;
	if (fwrite(raw_ip, 1, len, pcap->f) != len)
		return false;
	return true;
}
