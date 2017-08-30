#ifndef _UDP_H
#define _UDP_H

#include "uv.h"

int udp_start(struct tundev_context *ctx, uv_loop_t *loop);
void udp_stop(struct tundev_context *ctx);
void udp_send(struct tundev_context *ctx, uint8_t *buf, int len, struct sockaddr *addr);

#endif // for #ifndef _UDP_H
