#ifndef _TCP_H
#define _TCP_H

#include "uv.h"

int tcp_client_start(struct tundev_context *ctx, uv_loop_t *loop);
void tcp_client_stop(struct tundev_context *ctx);
void tcp_client_connect(struct tundev_context *ctx);
void tcp_client_send(struct tundev_context *ctx, uint8_t *buf, int len);

int tcp_server_start(struct tundev_context *ctx, uv_loop_t *loop);
void tcp_server_stop(struct tundev_context *ctx);
void tcp_server_send(struct peer *peer, uint8_t *buf, int len);

void tcp_send(uv_stream_t *stream, uint8_t *buf, int len);

#endif // for #ifndef _TCP_H
