#include "assert.h"
#include "uv.h"

#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "util.h"
#include "tun.h"
#ifdef ANDROID
#include "android.h"
#endif


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
close_cb(uv_handle_t *handle) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              inet_tcp.handle);
    ctx->connect = DISCONNECTED;
}

static void
disconnect(struct tundev_context *ctx) {
    uv_close(&ctx->inet_tcp.handle, close_cb);
}

static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              inet_tcp.handle);
    packet_alloc(&ctx->packet, buf);
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
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "Receive from server failed: %s",
                       uv_strerror(nread));
        }
        disconnect(ctx);
    }

    return;

err:
    logger_log(LOG_ERR, "Invalid tcp packet");
    disconnect(ctx);
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
    int rc;

    uv_tcp_init(ctx->timer.loop, &ctx->inet_tcp.tcp);

    ctx->inet_tcp_fd = create_socket(SOCK_STREAM, 0);
    if ((rc = uv_tcp_open(&ctx->inet_tcp.tcp, ctx->inet_tcp_fd))) {
        logger_log(LOG_ERR, "tcp open error: %s", uv_strerror(rc));
        exit(1);
    }

#ifdef ANDROID
    rc = protect_socket(ctx->inet_tcp_fd);
    logger_log(rc ? LOG_INFO : LOG_ERR, "Protect socket %s",
               rc ? "successful" : "failed");
    logger_log(LOG_INFO, "Connect to server...");
#endif

    rc = uv_tcp_nodelay(&ctx->inet_tcp.tcp, 1);
    rc = uv_tcp_keepalive(&ctx->inet_tcp.tcp, 1, 60);

    rc = uv_tcp_connect(&ctx->connect_req, &ctx->inet_tcp.tcp, &ctx->tun->addr,
                        connect_cb);
    if (rc) {
        /* TODO: start timer */
        logger_log(LOG_ERR, "Connect to server error: %s", uv_strerror(rc));
    } else {
        ctx->connect = CONNECTING;
    }
}

int
tcp_client_start(struct tundev_context *ctx, uv_loop_t *loop) {
    ctx->interval = 5;
    ctx->packet.buf = malloc(ctx->tun->mtu + OVERHEAD_BYTES);
    ctx->packet.max = ctx->tun->mtu + PRIMITIVE_BYTES;
    uv_timer_init(loop, &ctx->timer);
    connect_to_server(ctx);
    return 0;
}

void
tun_to_tcp_server(struct tundev_context *ctx, uint8_t *buf, int len) {
    tun_to_tcp(buf, len, &ctx->inet_tcp.stream);
}
