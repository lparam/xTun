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


#define DISCONNECTED   0
#define CONNECTING     1
#define CONNECTED      2

#define MAX_RETRY_INTERVAL 300

typedef struct tcp_client {
    int status;
    int connect_interval;
    int keepalive_interval;
    int inet_tcp_fd;
    struct sockaddr *server_addr;
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } inet_tcp;
    uv_connect_t connect_req;
    uv_timer_t timer_keepalive;
    uv_timer_t timer_reconnect;
    buffer_t recv_buffer;
    cipher_ctx_t *cipher_e;
    cipher_ctx_t *cipher_d;
    tundev_context_t *tun_ctx;
} tcp_client_t;

tcp_client_t *
tcp_client_new(tundev_context_t *ctx, struct sockaddr *addr) {
    tcp_client_t *c = malloc(sizeof *c);
    memset(c, 0, sizeof *c);
    buffer_alloc(&c->recv_buffer, ctx->tun->mtu + CRYPTO_MAX_OVERHEAD);
    c->cipher_e = cipher_new();
    c->cipher_d = cipher_new();
    c->connect_interval = 5;
    c->tun_ctx = ctx;
    c->server_addr = addr;
    c->keepalive_interval = ctx->tun->keepalive_interval;
    return c;
}

void
tcp_client_free(tcp_client_t *c) {
    cipher_free(c->cipher_e);
    cipher_free(c->cipher_d);
    buffer_free(&c->recv_buffer);
    free(c);
}

static void
timer_expire(uv_timer_t *handle) {
    tcp_client_t *c = container_of(handle, tcp_client_t, timer_reconnect);
    tcp_client_connect(c);
}

static void
reconnect(tcp_client_t *c) {
    c->connect_interval *= 2;
    int timeout = c->connect_interval < MAX_RETRY_INTERVAL ?
                  c->connect_interval : MAX_RETRY_INTERVAL;
    uv_timer_start(&c->timer_reconnect, timer_expire, timeout * 1000, 0);
}

static void
close_cb(uv_handle_t *handle) {
    tcp_client_t *c = container_of(handle, tcp_client_t, inet_tcp.handle);
    c->status = DISCONNECTED;
}

static void
tcp_client_disconnect(tcp_client_t *c) {
    uv_close(&c->inet_tcp.handle, close_cb);
}

static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    tcp_client_t *c = container_of(handle, tcp_client_t, inet_tcp.handle);
    buf->base = (char *)c->recv_buffer.data + c->recv_buffer.len;
    buf->len = c->recv_buffer.capacity - c->recv_buffer.len;
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tcp_client_t *client = container_of(stream, tcp_client_t, inet_tcp);

    if (nread > 0) {
        client->recv_buffer.len += nread;
        for (;;) {
            packet_t packet = {
                .size = 0,
            };
            int rc = packet_parse(&client->recv_buffer, &packet, client->cipher_d);
            if (rc == PACKET_UNCOMPLETE) {
                return;
            } else if (rc == PACKET_INVALID) {
                goto error;
            }

            tun_write(client->tun_ctx->tunfd, packet.buf, packet.size);

            int remain = client->recv_buffer.len - client->recv_buffer.off;
            assert(remain >= 0);
            if (remain > 0) {
                logger_log(LOG_NOTICE, "remain: %d", remain);
                memmove(client->recv_buffer.data,
                        client->recv_buffer.data + client->recv_buffer.off,
                        remain);
            }
            client->recv_buffer.len = remain;
            client->recv_buffer.off = 0;
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "Receive from server failed (%d: %s)",
                       nread, uv_strerror(nread));
        }
        tcp_client_disconnect(client);
    }

    return;

error:
    logger_log(LOG_ERR, "Invalid tcp packet");
    if (verbose) {
        dump_hex(client->recv_buffer.data, client->recv_buffer.len, "Invalid tcp Packet");
    }
    tcp_client_disconnect(client);
}

static void
tcp_client_recv(tcp_client_t *c) {
    uv_read_start(&c->inet_tcp.stream, alloc_cb, recv_cb);
}

static void
keepalive(uv_timer_t *handle) {
    tcp_client_t *c = container_of(handle, tcp_client_t, timer_keepalive);
    if (c->status != CONNECTED) {
        if (c->status == DISCONNECTED) {
            tcp_client_connect(c);
        }
        return;
    }
    size_t len = sizeof(struct iphdr) + 1;
    buffer_t buf;
    buffer_alloc(&buf, len);
    buf.len = len;
    construct_keepalive_packet(c->tun_ctx->tun, buf.data);
    tcp_send(&c->inet_tcp.stream, &buf, c->cipher_e);
}

static void
connect_cb(uv_connect_t *req, int status) {
    tcp_client_t *c = container_of(req, tcp_client_t, connect_req);
    if (status == 0) {
        c->connect_interval = 5;
        c->status = CONNECTED;
        uv_timer_stop(&c->timer_reconnect);
        cipher_reset(c->cipher_e);
        cipher_reset(c->cipher_d);
        buffer_reset(&c->recv_buffer);
        tcp_client_recv(c);
    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "Connect to server failed (%d: %s)",
                       status, uv_strerror(status));
            uv_close(&c->inet_tcp.handle, NULL);
            reconnect(c);
        }
    }
}

void
tcp_client_connect(tcp_client_t *c) {
    int rc;

    uv_tcp_init(c->timer_reconnect.loop, &c->inet_tcp.tcp);

    c->inet_tcp_fd = create_socket(SOCK_STREAM, 0);
    if (c->inet_tcp_fd < 0) {
        logger_stderr("Create socket - %s", strerror(errno));
        return;
    }
    if ((rc = uv_tcp_open(&c->inet_tcp.tcp, c->inet_tcp_fd))) {
        logger_log(LOG_ERR, "TCP open - %s", uv_strerror(rc));
        return;
    }

#ifdef ANDROID
    rc = protect_socket(c->inet_tcp_fd);
    logger_log(rc ? LOG_INFO : LOG_ERR, "Protect socket %s",
               rc ? "successful" : "failed");
    logger_log(LOG_INFO, "Connect to server...");
#endif

    rc = uv_tcp_nodelay(&c->inet_tcp.tcp, 1);
    rc = uv_tcp_keepalive(&c->inet_tcp.tcp, 1, 60);

    rc = uv_tcp_connect(&c->connect_req, &c->inet_tcp.tcp, c->server_addr, connect_cb);
    if (rc) {
        /* TODO: start timer */
        logger_log(LOG_ERR, "Connect to server error (%d: %s)",
                   rc, uv_strerror(rc));
    } else {
        c->status = CONNECTING;
    }
}

int
tcp_client_start(tcp_client_t *c, uv_loop_t *loop) {
    uv_timer_init(loop, &c->timer_reconnect);
    if (c->keepalive_interval) {
        uint64_t timeout = c->keepalive_interval * 1000;
        uv_timer_init(loop, &c->timer_keepalive);
        uv_timer_start(&c->timer_keepalive, keepalive, timeout, timeout);
    }
    tcp_client_connect(c);
    return 0;
}

void
tcp_client_stop(tcp_client_t *c) {
    if (uv_is_active(&c->inet_tcp.handle)) {
        uv_close(&c->inet_tcp.handle, NULL);
    }
    uv_close((uv_handle_t *) &c->timer_reconnect, NULL);
    if (c->keepalive_interval) {
        uv_close((uv_handle_t *) &c->timer_keepalive, NULL);
    }
}

void
tcp_client_send(tcp_client_t *c, buffer_t *buf) {
    tcp_send(&c->inet_tcp.stream, buf, c->cipher_e);
}

int tcp_client_connected(tcp_client_t *t) {
    return t->status == CONNECTED;
}

int tcp_client_disconnected(tcp_client_t *t) {
    return t->status == DISCONNECTED;
}