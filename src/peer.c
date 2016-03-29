#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "peer.h"

#define HASHSIZE 256

static uint32_t
hash_peer(uint32_t addr) {
	uint32_t a = addr >> 24;
	uint32_t b = addr >> 12;
	uint32_t c = addr;
	return (a + b + c) % HASHSIZE;
}

struct peer *
lookup_peer(uint32_t addr, struct peer **peers) {
	int h = hash_peer(addr);
	struct peer *p = peers[h];
	if (p == NULL)
		return NULL;
	if (p->tun_addr.s_addr == addr)
		return p;
	struct peer *last = p;
	while (last->next) {
		p = last->next;
        if (p->tun_addr.s_addr == addr)
			return p;
		last = p;
	}
	return NULL;
}

struct peer *
save_peer(uint32_t tun_addr, struct sockaddr *remote_addr, struct peer **peers)
{
	int h = hash_peer(tun_addr);
	struct peer *p = malloc(sizeof(struct peer));
	memset(p, 0, sizeof(*p));
    p->tun_addr.s_addr = tun_addr;
    p->remote_addr = *remote_addr;
	p->next = peers[h];
	peers[h] = p;
    return p;
}

void
destroy_peers(struct peer **peers) {
	for (int i = 0; i < HASHSIZE; i++) {
        struct peer *p = peers[i];
        while (p) {
            void *tmp = p;
            p = p->next;
            free(tmp);
        }
		peers[i] = NULL;
	}
}

void
init_peers(struct peer **peers) {
    for (int i = 0; i < HASHSIZE; i++) {
        peers[i] = NULL;
    }
}
