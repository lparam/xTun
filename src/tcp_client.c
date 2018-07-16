#include <assert.h>
#include <string.h>

#include "uv.h"

#include "common.h"
#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "util.h"
#include "tun.h"
#include "tcp.h"
#ifdef ANDROID
#include "android.h"
#endif


typedef struct  {
    buffer_t recv_buffer;
} client_t;

static void
timer_expire(uv_timer_t *handle) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              timer_reconnect);
    tcp_client_connect(ctx);
}

static void
reconnect(struct tundev_context *ctx) {
    ctx->interval *= 2;
    int timeout = ctx->interval < MAX_RETRY_INTERVAL ?
                  ctx->interval : MAX_RETRY_INTERVAL;
    uv_timer_start(&ctx->timer_reconnect, timer_expire, timeout * 1000, 0);
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
    buf->base = (char *)ctx->recv_buffer.data + ctx->recv_buffer.len;
    buf->len = sizeof(ctx->recv_buffer.data) - ctx->recv_buffer.len;
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct tundev_context *ctx = container_of(stream, struct tundev_context,
                                              inet_tcp);

    if (nread > 0) {
        ctx->recv_buffer.len += nread;
        for (;;) {
            packet_t packet;
            int rc = packet_parse(&ctx->recv_buffer, &packet);
            if (rc == PACKET_UNCOMPLETE) {
                return;
            } else if (rc == PACKET_INVALID) {
                goto err;
            }

            int clen = packet.size;
            int mlen = packet.size - PRIMITIVE_BYTES;
            uint8_t *c = packet.buf, *m = packet.buf;

            assert(mlen > 0 && mlen <= ctx->tun->mtu);

            int err = crypto_decrypt(m, c, clen);
            if (err) {
                goto err;
            }

            tun_write(ctx->tunfd, m, mlen);

            int remain = ctx->recv_buffer.len - ctx->recv_buffer.off;
            assert(remain >= 0);
            if (remain > 0) {
                memmove(ctx->recv_buffer.data,
                        ctx->recv_buffer.data + ctx->recv_buffer.off, remain);
            }
            ctx->recv_buffer.len = remain;
            ctx->recv_buffer.off = 0;
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "Receive from server failed (%d: %s)",
                       nread, uv_strerror(nread));
        }
        disconnect(ctx);
    }

    return;

err:
    logger_log(LOG_ERR, "Invalid tcp packet");
    if (verbose) {
        dump_hex(buf->base, nread, "Invalid tcp Packet");
    }
    disconnect(ctx);
}

static void
receive_from_server(struct tundev_context *ctx) {
    uv_read_start(&ctx->inet_tcp.stream, alloc_cb, recv_cb);
}

static void
keepalive(uv_timer_t *handle) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              timer_keepalive);
    if (ctx->connect != CONNECTED) {
        if (ctx->connect == DISCONNECTED) {
            tcp_client_connect(ctx);
        }
        return;
    }
    size_t len = sizeof(struct iphdr) + PRIMITIVE_BYTES + 1;
    uint8_t *buf = calloc(1, len);
    construct_keepalive_packet(ctx->tun, buf + PRIMITIVE_BYTES);
    crypto_encrypt(buf, buf + PRIMITIVE_BYTES, len - PRIMITIVE_BYTES);
    tcp_send(&ctx->inet_tcp.stream, buf, len);
}

static void
connect_cb(uv_connect_t *req, int status) {
    struct tundev_context *ctx = container_of(req, struct tundev_context,
                                              connect_req);
    if (status == 0) {
        ctx->interval = 5;
        ctx->connect = CONNECTED;
        uv_timer_stop(&ctx->timer_reconnect);
        receive_from_server(ctx);
    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "Connect to server failed (%d: %s)",
                       status, uv_strerror(status));
            uv_close(&ctx->inet_tcp.handle, NULL);
            reconnect(ctx);
        }
    }
}

void
tcp_client_connect(struct tundev_context *ctx) {
    int rc;

    uv_tcp_init(ctx->timer_reconnect.loop, &ctx->inet_tcp.tcp);

    ctx->inet_tcp_fd = create_socket(SOCK_STREAM, 0);
    if (ctx->inet_tcp_fd < 0) {
        logger_stderr("Create socket - %s", strerror(errno));
        return;
    }
    if ((rc = uv_tcp_open(&ctx->inet_tcp.tcp, ctx->inet_tcp_fd))) {
        logger_log(LOG_ERR, "TCP open - %s", uv_strerror(rc));
        return;
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
        logger_log(LOG_ERR, "Connect to server error (%d: %s)",
                   rc, uv_strerror(rc));
    } else {
        ctx->connect = CONNECTING;
    }
}

int
tcp_client_start(struct tundev_context *ctx, uv_loop_t *loop) {
    ctx->interval = 5;
    memset(&ctx->recv_buffer, 0, sizeof ctx->recv_buffer);
    uv_timer_init(loop, &ctx->timer_reconnect);
    if (ctx->tun->keepalive_delay) {
        uint64_t timeout = ctx->tun->keepalive_delay * 1000;
        uv_timer_init(loop, &ctx->timer_keepalive);
        uv_timer_start(&ctx->timer_keepalive, keepalive, timeout, timeout);
    }
    tcp_client_connect(ctx);
    return 0;
}

void
tcp_client_stop(struct tundev_context *ctx) {
    if (uv_is_active(&ctx->inet_tcp.handle)) {
        uv_close(&ctx->inet_tcp.handle, NULL);
    }
    uv_close((uv_handle_t *) &ctx->timer_reconnect, NULL);
    if (ctx->tun->keepalive_delay) {
        uv_close((uv_handle_t *) &ctx->timer_keepalive, NULL);
    }
}

void
tcp_client_send(struct tundev_context *ctx, uint8_t *buf, int len) {
    tcp_send(&ctx->inet_tcp.stream, buf, len);
}
