#ifndef TUN_H
#define TUN_H

#include <netinet/ip.h>

#include "uv.h"

#include "rwlock.h"
#include "peer.h"


/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 24 (xTun) */
/* #define MTU 1440 */

/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 20 (TCP) - 42 (xTun) */
#define MTU 1410

#define xTUN_MIN_MTU    1410
#define xTUN_MAX_MTU    2048

typedef struct tundev tundev_t;
typedef struct tundev_ctx tundev_ctx_t;

typedef enum rmode_t {
   RMODE_CLIENT = 0x1,
   RMODE_SERVER,
} rmode_t;

typedef enum protocol_t {
   PROTOCOL_TCP = 0x1,
   PROTOCOL_UDP,
} protocol_t;

typedef struct peer_addr {
    char node[128];
    int port;
    struct sockaddr addr;
} peer_addr_t;

extern uv_rwlock_t clients_rwlock;
extern rwlock_t peers_rwlock;
extern peer_t *peers[HASHSIZE];

extern int debug;
extern int verbose;
extern int multicast;
extern uint32_t nf_mark;
extern rmode_t mode;
extern protocol_t protocol;

#ifdef ANDROID
extern int dns_global;
extern struct sockaddr dns_server;
#endif

int tun_write(tundev_ctx_t *ctx, uint8_t *buf, ssize_t len);
int tun_network_check(struct tundev_ctx *ctx, struct iphdr *iphdr);

#endif // for #ifndef TUN_H
