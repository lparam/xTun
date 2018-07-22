#ifndef _PEER_H
#define _PEER_H

#include "uv.h"

typedef struct peer {
    int protocol;
    struct in_addr tun_addr;
	struct sockaddr remote_addr;
	struct peer *next;
    void *data;
} peer_t;

void init_peers(peer_t **peers);
void destroy_peers(peer_t **peers);
peer_t * lookup_peer(uint32_t addr, peer_t **peers);
peer_t * save_peer(uint32_t tun_addr, struct sockaddr *remote_addr,
                   peer_t**peers);
#endif // for #ifndef _PEER_H
