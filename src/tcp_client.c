#include "uv.h"

#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "util.h"
#include "tun.h"


static void
timer_expire(uv_timer_t *handle) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              timer);
    connect_to_server(ctx);
}

static void
reconnect(struct tundev_context *ctx) {
    ctx->interval *= 2;
    int timeout = ctx->interval < MAX_RETRY_INTERVAL ?
                  ctx->interval : MAX_RETRY_INTERVAL;
    uv_timer_start(&ctx->timer, timer_expire, timeout * 1000, 0);
}

static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              inet_tcp.handle);
    struct packet *packet = &ctx->packet;
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
        logger_log(LOG_ERR, "Send to server failed: %s", uv_strerror(status));
        struct tundev_context *ctx = req->data;
        ctx->connect = DISCONNECTED;
    }
    uv_buf_t *buf = (uv_buf_t *) (req + 1);
    free(buf->base);
    free(req);
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct tundev_context *ctx = container_of(stream, struct tundev_context,
                                              inet_tcp);

    if (nread > 0) {
        struct packet *packet = &ctx->packet;
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

        network_to_tun(ctx->tunfd, m, mlen);

        packet_reset(packet);

    } else if (nread < 0) {
        ctx->connect = DISCONNECTED;
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "Receive from server failed: %s",
                       uv_strerror(nread));
        }
    }

    return;

err:
    logger_log(LOG_ERR, "Invalid tcp packet");
}

static void
receive_from_server(struct tundev_context *ctx) {
    packet_reset(&ctx->packet);
    uv_read_start(&ctx->inet_tcp.stream, alloc_cb, recv_cb);
}

static void
connect_cb(uv_connect_t *req, int status) {
    struct tundev_context *ctx = container_of(req, struct tundev_context,
                                              connect_req);
    if (status == 0) {
        ctx->interval = 5;
        ctx->connect = CONNECTED;
        uv_timer_stop(&ctx->timer);
        receive_from_server(ctx);
    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "Connect to server failed: %s",
                       uv_strerror(status));
            uv_close(&ctx->inet_tcp.handle, NULL);
            reconnect(ctx);
        }
    }
}

void
connect_to_server(struct tundev_context *ctx) {
    ctx->connect = CONNECTING;
    uv_tcp_init(ctx->timer.loop, &ctx->inet_tcp.tcp);
    int rc = uv_tcp_connect(&ctx->connect_req, &ctx->inet_tcp.tcp,
                            &ctx->tun->addr, connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "Connect to server error: %s", uv_strerror(rc));
        exit(1);
    }
}

int
tcp_client_start(struct tundev_context *ctx, uv_loop_t *loop) {
    ctx->interval = 5;
    uv_timer_init(loop, &ctx->timer);
    connect_to_server(ctx);
    return 0;
}

void
tun_to_tcp_server(struct tundev_context *ctx, uint8_t *buf, int len) {
    uv_write_t *req = malloc(sizeof(*req) + sizeof(uv_buf_t));

    uv_buf_t *outbuf = (uv_buf_t *) (req + 1);
    outbuf->base = (char *) buf;
    outbuf->len = len;

    uint8_t hdr[2];
    write_size(hdr, len);

    uv_buf_t bufs[2] = {
        uv_buf_init((char *) hdr, 2),
        *outbuf,
    };

    req->data = ctx;
    uv_write(req, &ctx->inet_tcp.stream, bufs, 2, send_cb);
}
