#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "peer.h"

#define HASHSIZE 256

static uint32_t
peer_hash(uint32_t addr) {
    uint32_t a = addr >> 24;
    uint32_t b = addr >> 12;
    uint32_t c = addr;
    return (a + b + c) % HASHSIZE;
}

peer_t *
peer_lookup(uint32_t addr, peer_t **peers) {
    int h = peer_hash(addr);
    peer_t *p = peers[h];
    if (p == NULL)
        return NULL;
    if (p->tun_addr.s_addr == addr)
        return p;
    peer_t *last = p;
    while (last->next) {
        p = last->next;
        if (p->tun_addr.s_addr == addr)
            return p;
        last = p;
    }
    return NULL;
}

peer_t *
peer_add(uint32_t tun_addr, struct sockaddr *remote_addr, peer_t **peers) {
    int h = peer_hash(tun_addr);
    peer_t *p = malloc(sizeof(peer_t));
    memset(p, 0, sizeof(*p));
    p->tun_addr.s_addr = tun_addr;
    p->remote_addr = *remote_addr;
    p->next = peers[h];
    peers[h] = p;
    return p;
}

void
peer_destroy(peer_t **peers) {
    for (int i = 0; i < HASHSIZE; i++) {
        peer_t *p = peers[i];
        while (p) {
            void *tmp = p;
            p = p->next;
            free(tmp);
        }
        peers[i] = NULL;
    }
}

void
peer_init(peer_t **peers) {
    for (int i = 0; i < HASHSIZE; i++) {
        peers[i] = NULL;
    }
}
