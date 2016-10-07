#include <stdlib.h>
#include <stdbool.h>

typedef struct pcap_file pcap_file;

/**
 * Open a pcap file for writing
 */
pcap_file *pcap_open(const char *fn);

/**
 * Close a pcap file.
 * Accepts NULL (does nothing)
 */
void pcap_close(pcap_file *pcap);

/**
 * Write a raw IP packet to the pcap file
 */
bool pcap_write_ip(pcap_file *pcap,
		   const void *raw_ip, size_t len);
