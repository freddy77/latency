#include <stdint.h>

extern int connect_port;
extern uint64_t latency_us;
extern unsigned rate_bytes;

void handle_client(int fd, unsigned connection_id);
