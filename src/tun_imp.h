#ifndef TUN_IMP_H
#define TUN_IMP_H

#include "uv.h"
#include "packet.h"

struct tundev_context {
	int             tunfd;
    int             inet_fd;
    uint8_t        *network_buffer;
    uv_udp_t        inet;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
    } inet_tcp;
    uv_connect_t    connect_req;
    uv_poll_t       watcher;
    uv_sem_t        semaphore;
    uv_async_t      async_handle;
    struct packet  *packet;
    struct tundev  *tun;
};

struct tundev {
    char                   iface[128];
    char                   ifconf[128];
    int                    mode;
    int                    mtu;
    struct sockaddr        bind_addr;
    struct sockaddr        server_addr;
#ifdef ANDROID
    int                    is_global_proxy;
    struct sockaddr        dns_server;
#endif
    struct raddr          *raddrs[HASHSIZE];
    uint32_t               queues;
    struct tundev_context  contexts[0];
};


void network_to_tun(int tunfd, uint8_t *buf, ssize_t len);

#endif // for #ifndef TUN_IMP_H
