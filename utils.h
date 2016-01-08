#include <time.h>
#include <inttypes.h>

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

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
