#ifndef TUN_H
#define TUN_H

#include "uv.h"
#include "packet.h"


/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 24 (xTun) */
/* #define MTU 1440 */

/* MTU of VPN tunnel device. Use the following formula to calculate:
   1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 20 (TCP) - 26 (xTun) */
#define MTU 1426

#define HASHSIZE 256

#define DISCONNECTED   0
#define CONNECTING     1
#define CONNECTED      2

#define MAX_RETRY_INTERVAL 300

#define xTUN_CLIENT		0x01
#define xTUN_SERVER     0x02
#define xTUN_TCP        0x01
#define xTUN_UDP        0x02

struct tundev_context {
	int             tunfd;
    int             inet_tcp_fd;
    int             inet_udp_fd;
    int             connect;        /* TCP client */
    int             interval;
    uint8_t        *network_buffer; /* UDP */
    struct          packet packet;  /* TCP client */
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } inet_tcp;
    uv_udp_t        inet_udp;
    uv_connect_t    connect_req;
    uv_shutdown_t   shutdown_req;
    uv_poll_t       watcher;
    uv_sem_t        semaphore;
    uv_async_t      async_handle;
    uv_timer_t      timer;
    struct tundev  *tun;
};

struct tundev {
    char                   iface[128];
    char                   ifconf[128];
    int                    mode;
    int                    mtu;
    in_addr_t              network;
    in_addr_t              netmask;
    struct sockaddr        addr;
#ifdef ANDROID
    int                    global;
    struct sockaddr        dns_server;
#endif
    uint32_t               queues;
    struct tundev_context  contexts[0];
};

uv_rwlock_t rwlock;
struct peer *peers[HASHSIZE];

int verbose;
int protocol;
uint8_t mode;

void network_to_tun(int tunfd, uint8_t *buf, ssize_t len);

void connect_to_server(struct tundev_context *ctx);
void tun_to_tcp_client(struct peer *peer, uint8_t *buf, int len);
void tun_to_tcp_server(struct tundev_context *ctx, uint8_t *buf, int len);
void tun_to_tcp(uint8_t *buf, int len, uv_stream_t *stream);
void tun_to_udp(struct tundev_context *ctx, uint8_t *buf, int len,
                struct sockaddr *addr);

int udp_start(struct tundev_context *ctx, uv_loop_t *loop);
int tcp_client_start(struct tundev_context *ctx, uv_loop_t *loop);
int tcp_server_start(struct tundev_context *ctx, uv_loop_t *loop);

#ifdef ANDROID
int protect_socket(int fd);
#endif

#endif // for #ifndef TUN_H
