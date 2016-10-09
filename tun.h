#include <stdbool.h>

void tun_setup(bool local_mode);
void tun_set_client(const char *ip, int port);
void tun_set_server(int port);

void handle_tun(void);
