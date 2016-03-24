#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "uv.h"

#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "util.h"
#include "tun.h"
#include "tun_imp.h"


static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct packet *packet = handle->data;
    if (packet->size) {
        buf->base = (char *) packet->buf + packet->offset;
        buf->len = packet->size - packet->offset;
    } else {
        buf->base = (char *) packet->buf + (packet->read ? 1 : 0);
        buf->len = packet->read ? 1 : HEADER_BYTES;
    }
}

static void
send_cb(uv_write_t *req, int status) {
    if (status) {
        /* TODO: reconnect to server */
        logger_log(LOG_ERR, "send to server failed: %s", uv_strerror(status));
    }
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        struct packet *packet = stream->data;
        int rc = packet_filter(packet, buf->base, nread);
        if (rc == PACKET_UNCOMPLETE) {
            return;
        } else if (rc == PACKET_INVALID) {
            goto err;
        }

        int clen = packet->size;
        int mlen = packet->size - PRIMITIVE_BYTES;
        uint8_t *c = packet->buf, *m = packet->buf;

        int err = crypto_decrypt(m, c, clen);
        if (err) {
            goto err;
        }

        struct tundev_context *ctx = container_of(stream,
                                                  struct tundev_context,
                                                  inet_tcp);
        network_to_tun(ctx->tunfd, m, mlen);

    } else if (nread < 0) {
        /* TODO: reconnect to server */
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "receive from server failed: %s",
                       uv_strerror(nread));
        }
    }

    return;

err:
    logger_log(LOG_ERR, "invalid tcp packet");
}

static void
receive_from_server(struct tundev_context *ctx) {
    packet_reset(ctx->packet);
    ctx->inet_tcp.stream.data = ctx->packet;
    uv_read_start(&ctx->inet_tcp.stream, alloc_cb, recv_cb);
}

static void
connect_cb(uv_connect_t *req, int status) {
    if (status == 0) {
        struct tundev_context *ctx = container_of(req, struct tundev_context,
                                                  connect_req);
        receive_from_server(ctx);
    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "connect to server failed: %s",
                       uv_strerror(status));
        }
    }
}

static void
connect_to_server(struct tundev_context *ctx) {
    struct tundev *tun = ctx->tun;
    int rc = uv_tcp_connect(&ctx->connect_req, &ctx->inet_tcp.tcp,
                            &tun->server_addr, connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "connect to server error: %s", uv_strerror(rc));
    }
}

static int
tcp_start(struct tundev *tun, uv_loop_t *loop) {
    struct tundev_context *ctx = tun->contexts;
    connect_to_server(ctx);
    return 0;
}

void
tun_to_tcp(struct tundev_context *ctx, uint8_t *buf, int buflen) {
    buf -= HEADER_BYTES;
    write_size(buf, buflen);
    buflen += HEADER_BYTES;
    uv_buf_t data = uv_buf_init((char *) buf, buflen);
    uv_write(&ctx->write_req, (uv_stream_t *) &ctx->inet_tcp, &data, 1,
             send_cb);
}
