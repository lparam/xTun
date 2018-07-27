#ifndef TUN_H
#define TUN_H

#include "uv.h"
#include "packet.h"
#include "peer.h"
#include "udp.h"
#include "tcp.h"


/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 24 (xTun) */
/* #define MTU 1440 */

/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 20 (TCP) - 42 (xTun) */
#define MTU 1410

#define XTUN_MIN_MTU    1410
#define XTUN_MAX_MTU    2048

#define HASHSIZE 256

#define xTUN_CLIENT		0x01
#define xTUN_SERVER     0x02
#define xTUN_TCP        0x01
#define xTUN_UDP        0x02

#define xTUN_KEEPALIVE "xTun-keepalive"

typedef struct tundev_ctx {
    uv_poll_t        watcher;
    uv_sem_t         semaphore;
    uv_async_t       async_handle;

    udp_t           *udp;
    tcp_server_t    *tcp_server;
    tcp_client_t    *tcp_client;

    int              tunfd;
    struct tundev   *tun;
} tundev_ctx_t;

typedef struct tundev {
    char                   iface[128];
    char                   ifconf[128];
    int                    mtu;
    int                    keepalive_interval;
    in_addr_t              addr;
    in_addr_t              network;
    in_addr_t              netmask;

    uint32_t               queues;
    struct tundev_ctx      contexts[0];
} tundev_t;

uv_rwlock_t clients_rwlock;
uv_rwlock_t peers_rwlock;
peer_t *peers[HASHSIZE];

int verbose;
int protocol;
uint8_t mode;

#ifdef ANDROID
    int dns_global;
    struct sockaddr dns_server;
#endif

int tun_write(int tunfd, uint8_t *buf, ssize_t len);

#endif // for #ifndef TUN_H
