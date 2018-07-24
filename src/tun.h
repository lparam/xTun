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
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 20 (TCP) - 26 (xTun) */
#define MTU 1426

#define XTUN_MAX_MTU    10000

#define HASHSIZE 256

#define xTUN_CLIENT		0x01
#define xTUN_SERVER     0x02
#define xTUN_TCP        0x01
#define xTUN_UDP        0x02

typedef struct tundev_context {
    uv_poll_t       watcher;
    uv_sem_t        semaphore;
    uv_async_t      async_handle;

    udp_t           *udp;
    tcp_server_t    *tcp_server;
    tcp_client_t    *tcp_client;

    // TODO: Add buffer
    // buffer_t buffer;
    // int ready;

    int             tunfd;
    struct tundev  *tun;
} tundev_context_t;

struct tundev {
    char                   iface[128];
    char                   ifconf[128];
    int                    mtu;
    int                    keepalive_interval;
    in_addr_t              addr;
    in_addr_t              network;
    in_addr_t              netmask;
#ifdef ANDROID
    int                    global;
    struct sockaddr        dns_server;
#endif
    uint32_t               queues;
    struct tundev_context  contexts[0];
};

uv_rwlock_t rwlock;
peer_t *peers[HASHSIZE];

int verbose;
int protocol;
uint8_t mode;

int tun_write(int tunfd, uint8_t *buf, ssize_t len);

#endif // for #ifndef TUN_H
