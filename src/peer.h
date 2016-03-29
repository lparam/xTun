#ifndef CLIENT_H
#define CLIENT_H

#include "uv.h"

struct peer {
    int protocol;
    struct in_addr tun_addr;
	struct sockaddr remote_addr;
	struct peer *next;
    void *data;
};

void init_peers(struct peer **peers);
void destroy_peers(struct peer **peers);
struct peer * lookup_peer(uint32_t addr, struct peer **peers);
struct peer * save_peer(uint32_t tun_addr, struct sockaddr *remote_addr,
                        struct peer **peers);

#endif // for #ifndef CLIENT_H
