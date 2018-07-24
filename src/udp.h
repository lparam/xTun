#ifndef _UDP_H
#define _UDP_H

#include "uv.h"
#include "buffer.h"

typedef struct udp udp_t;
typedef struct tundev_context tundev_context_t;

udp_t *udp_new(tundev_context_t *tun, struct sockaddr *addr);
void udp_free();
int udp_start(udp_t *udp, uv_loop_t *loop);
void udp_stop(udp_t *udp);
void udp_send(udp_t *udp, buffer_t *buf, struct sockaddr *addr);

#endif // for #ifndef _UDP_H
