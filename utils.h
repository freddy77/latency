#include <time.h>
#include <inttypes.h>

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define IP(a,b,c,d) ((a)*0x1000000u+(b)*0x10000u+(c)*0x100u+(d)*1u)

void set_nonblocking(int sock);
void set_nodelay(int fd);
void write_all(int fd, const void *buf, size_t buf_size);

static inline uint64_t
get_time_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000000u + ts.tv_nsec / 1000u;
}

typedef struct {
	const char *suffix;
	double scale;
} unit;

int parse_value(const char *s, int min, int max, const unit *units);
