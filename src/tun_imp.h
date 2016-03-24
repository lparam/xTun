#ifndef TUN_IMP_H
#define TUN_IMP_H

#include "uv.h"
#include "packet.h"

struct tundev_context {
	int             tunfd;
    int             inet_fd;
    uint8_t        *network_buffer; /* UDP */
    struct          packet packet;  /* TCP */
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } inet_tcp;
    uv_udp_t        inet_udp;
    uv_connect_t    connect_req;
    uv_poll_t       watcher;
    uv_sem_t        semaphore;
    uv_async_t      async_handle;
    struct tundev  *tun;
};

struct tundev {
    char                   iface[128];
    char                   ifconf[128];
    int                    mode;
    int                    mtu;
    struct sockaddr        addr;
#ifdef ANDROID
    int                    global;
    struct sockaddr        dns_server;
#endif
    uint32_t               queues;
    struct tundev_context  contexts[0];
};

#ifdef XTUND
#define HASHSIZE 256

struct peer *peers[HASHSIZE];
uv_rwlock_t rwlock;
#else
int tcp;
#endif

void network_to_tun(int tunfd, uint8_t *buf, ssize_t len);
#ifdef XTUND
void tun_to_tcp_client(struct peer *peer, uint8_t *buf, int len);
#endif
void tun_to_tcp_server(struct tundev_context *ctx, uint8_t *buf, int len);
void tun_to_udp(struct tundev_context *ctx, uint8_t *buf, int len,
                struct sockaddr *addr);

int tcp_start(struct tundev_context *ctx, uv_loop_t *loop);
int udp_start(struct tundev_context *ctx, uv_loop_t *loop);

#endif // for #ifndef TUN_IMP_H
