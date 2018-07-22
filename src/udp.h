#ifndef _UDP_H
#define _UDP_H

#include "uv.h"

typedef struct udp udp_t;
typedef struct tundev_context tundev_context_t;

udp_t *udp_new(tundev_context_t *tun, struct sockaddr *addr);
void udp_free();
int udp_start(udp_t *udp, uv_loop_t *loop);
void udp_stop(udp_t *udp);
void udp_send(udp_t *udp, uint8_t *buf, int len, struct sockaddr *addr);

#endif // for #ifndef _UDP_H
