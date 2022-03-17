#ifndef _PEER_H
#define _PEER_H

#include <netinet/in.h>
#include <sys/socket.h>


#define HASHSIZE 256

typedef struct peer {
    int protocol;
    struct in_addr tun_addr;
	struct sockaddr remote_addr;
	struct peer *next;
    void *data;
} peer_t;

void peer_init(peer_t **peers);
void peer_destroy(peer_t **peers);
peer_t * peer_lookup(uint32_t addr, peer_t **peers);
peer_t * peer_add(uint32_t tun_addr, struct sockaddr *remote_addr, peer_t**peers);

#endif // for #ifndef _PEER_H
