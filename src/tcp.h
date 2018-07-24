#ifndef _TCP_H
#define _TCP_H

#include "uv.h"
#include "buffer.h"
#include "crypto.h"
#include "peer.h"

typedef struct tcp_client tcp_client_t;
typedef struct tcp_server tcp_server_t;
typedef struct tundev_context tundev_context_t;

tcp_client_t * tcp_client_new(tundev_context_t *ctx, struct sockaddr *addr);
void tcp_client_free(tcp_client_t *c);
int tcp_client_start(tcp_client_t *c, uv_loop_t *loop);
void tcp_client_stop(tcp_client_t *c);
void tcp_client_connect(tcp_client_t *c);
void tcp_client_send(tcp_client_t *c, buffer_t *buf);
int tcp_client_connected();
int tcp_client_disconnected();

tcp_server_t * tcp_server_new(tundev_context_t *ctx, struct sockaddr *addr);
void tcp_server_free(tcp_server_t *s);
int tcp_server_start(tcp_server_t *s, uv_loop_t *loop);
void tcp_server_stop(tcp_server_t *s);
void tcp_server_send(peer_t *peer, buffer_t *buf);

void tcp_send(uv_stream_t *stream, buffer_t *buf, cipher_ctx_t *ctx);

#endif // for #ifndef _TCP_H
