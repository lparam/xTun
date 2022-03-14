#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "uv.h"

#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "rwlock.h"
#include "util.h"
#include "tun.h"
#include "tcp.h"
#ifdef ANDROID
#include "android.h"
#endif


#define DISCONNECTING  0
#define DISCONNECTED   1
#define CONNECTING     2
#define CONNECTED      3
#define RECONNECTING   4

#define DEFAULT_INTERVAL    5
#define MAX_RETRY_INTERVAL  80

typedef struct tcp_client {
    ATOM_INT status;
    int connect_interval;
    int keepalive_interval;
    int inet_tcp_fd;
    peer_addr_t *peer_addr;
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } inet_tcp;
    uv_connect_t connect_req;
    uv_timer_t timer_keepalive;
    uv_timer_t timer_reconnect;
    buffer_t recv_buffer;
    packet_t packet;
    cipher_ctx_t *cipher_e;
    cipher_ctx_t *cipher_d;
    tundev_ctx_t *tun_ctx;
} tcp_client_t;

tcp_client_t *
tcp_client_new(tundev_ctx_t *ctx, peer_addr_t *addr) {
    tcp_client_t *c = malloc(sizeof *c);
    memset(c, 0, sizeof *c);
    buffer_alloc(&c->recv_buffer, ctx->tun->mtu + CRYPTO_MAX_OVERHEAD);
    packet_reset(&c->packet);
    c->cipher_e = cipher_new();
    c->cipher_d = cipher_new();
    c->connect_interval = DEFAULT_INTERVAL;
    c->tun_ctx = ctx;
    c->peer_addr = addr;
    c->keepalive_interval = ctx->tun->keepalive_interval;
    ATOM_INIT(&c->status, DISCONNECTED);
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
tcp_client_reset(tcp_client_t *c) {
    c->connect_interval = DEFAULT_INTERVAL;
    cipher_reset(c->cipher_e);
    cipher_reset(c->cipher_d);
    buffer_reset(&c->recv_buffer);
    packet_reset(&c->packet);
}

static void
timer_expire(uv_timer_t *handle) {
    tcp_client_t *c = container_of(handle, tcp_client_t, timer_reconnect);
    assert(ATOM_LOAD(&c->status) == RECONNECTING);
    tcp_client_connect(c);
}

static void
tcp_client_reconnect(tcp_client_t *c) {
    assert(uv_timer_get_due_in(&c->timer_reconnect) == 0);
    ATOM_STORE(&c->status, RECONNECTING);
    logger_log(LOG_INFO, "Try to connect to the server after %d seconds", c->connect_interval);
    uv_timer_start(&c->timer_reconnect, timer_expire, c->connect_interval * 1000, 0);
    c->connect_interval *= 2;
    if (c->connect_interval > MAX_RETRY_INTERVAL) {
        c->connect_interval = DEFAULT_INTERVAL;
    }
}

static void
close_cb(uv_handle_t *handle) {
    logger_log(LOG_INFO, "TCP connection is closed");
    tcp_client_t *c = container_of(handle, tcp_client_t, inet_tcp.handle);
    ATOM_STORE(&c->status, DISCONNECTED);
}

static void
tcp_client_close(tcp_client_t *c) {
    ATOM_STORE(&c->status, DISCONNECTING);
    logger_log(LOG_INFO, "Close the TCP connection");
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
    tcp_client_t *c = container_of(stream, tcp_client_t, inet_tcp);

    if (nread <= 0) {
        if (nread < 0) {
            if (nread == UV_EOF) {
                logger_log(LOG_INFO, "The server is closed");
            } else {
                logger_log(LOG_ERR, "Receive from server (%d: %s)",
                           nread, uv_strerror(nread));
            }
            tcp_client_close(c);
        }
        return;
    }

    c->recv_buffer.len += nread;
    for (;;) {
        int rc = packet_parse(&c->packet, &c->recv_buffer, c->cipher_d);
        if (rc == PACKET_UNCOMPLETE) {
            break;
        } else if (rc == PACKET_INVALID) {
            logger_log(LOG_ERR, "Invalid tcp packet");
            if (verbose) {
                dump_hex(c->recv_buffer.data, c->recv_buffer.len,
                         "Invalid tcp Packet");
            }
            tcp_client_close(c);
            break;
        }

        tun_write(c->tun_ctx->tunfd, c->packet.buf, c->packet.size);

        int remain = c->recv_buffer.len - c->recv_buffer.off;
        if (remain > 0) {
            memmove(c->recv_buffer.data,
                    c->recv_buffer.data + c->recv_buffer.off, remain);
        }
        c->recv_buffer.len = remain;
        c->recv_buffer.off = 0;
        packet_reset(&c->packet);
    }
}

static void
tcp_client_recv(tcp_client_t *c) {
    uv_read_start(&c->inet_tcp.stream, alloc_cb, recv_cb);
}

static void
keepalive(uv_timer_t *handle) {
    tcp_client_t *c = container_of(handle, tcp_client_t, timer_keepalive);
    if (ATOM_LOAD(&c->status) != CONNECTED) {
        if (ATOM_LOAD(&c->status) == DISCONNECTED) {
            tcp_client_connect(c);
        }

    } else {
        buffer_t buf;
        packet_construct_keepalive(&buf, c->tun_ctx->tun);
        tcp_send(&c->inet_tcp.stream, &buf, c->cipher_e);
    }
}

static void
close_cb_reconnect(uv_handle_t *handle) {
    tcp_client_t *c = container_of(handle, tcp_client_t, inet_tcp.handle);
    ATOM_STORE(&c->status, DISCONNECTED);
    tcp_client_reconnect(c);
}

static void
connect_cb(uv_connect_t *req, int status) {
    tcp_client_t *c = container_of(req, tcp_client_t, connect_req);
    if (status == 0) {
        char remote[INET_ADDRSTRLEN + 1];
        int port = ip_name(&c->peer_addr->addr, remote, sizeof(remote));
        logger_log(LOG_INFO, "Successfully connected to server %s:%d", remote, port);
        ATOM_STORE(&c->status, CONNECTED);
        uv_timer_stop(&c->timer_reconnect);
        tcp_client_reset(c);
        tcp_client_recv(c);

    } else {
        logger_log(LOG_ERR, "Failed to Connect to server (%d: %s)",
                   status, uv_strerror(status));
        if (status != UV_ECANCELED) {
            uv_close(&c->inet_tcp.handle, close_cb_reconnect);
        }
    }
}

void
tcp_client_connect(tcp_client_t *c) {
    int rc;

    ATOM_STORE(&c->status, CONNECTING);

    uv_tcp_init(c->timer_reconnect.loop, &c->inet_tcp.tcp);

    c->inet_tcp_fd = create_socket(SOCK_STREAM, 0);
    if (c->inet_tcp_fd < 0) {
        logger_log(LOG_ERR, "Create socket - %s", strerror(errno));
        goto fail;
    }
    if (tcp_opts(c->inet_tcp_fd, nf_mark) != 0) {
        logger_log(LOG_ERR, "Set tcp opts - %s", strerror(errno));
        (void) close(c->inet_tcp_fd);
        goto fail;
    }
    if ((rc = uv_tcp_open(&c->inet_tcp.tcp, c->inet_tcp_fd))) {
        logger_log(LOG_ERR, "TCP open - %s", uv_strerror(rc));
        goto fail;
    }
    if (c->keepalive_interval) {
        if ((rc = uv_tcp_keepalive(&c->inet_tcp.tcp, 1, c->keepalive_interval * 1000))) {
            logger_log(LOG_ERR, "TCP keepalive - %s", uv_strerror(rc));
            goto fail;
        }
    }

#ifdef ANDROID
    rc = protect_socket(c->inet_tcp_fd);
    logger_log(rc ? LOG_INFO : LOG_ERR, "Protect socket %s",
               rc ? "successful" : "failed");
#endif

    logger_log(LOG_INFO, "Connect to server %s:%d ...", c->peer_addr->node, c->peer_addr->port);
    if (resolve_addr(c->peer_addr->node, c->peer_addr->port, &c->peer_addr->addr)) {
        goto fail;
    }
    rc = uv_tcp_connect(&c->connect_req, &c->inet_tcp.tcp, &c->peer_addr->addr, connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "Connect to server error (%d: %s)", rc, uv_strerror(rc));
        // set status to RECONNECTING in close_cb_reconnect
        uv_close(&c->inet_tcp.handle, close_cb_reconnect);
    }

    return;
fail:
    ATOM_STORE(&c->status, DISCONNECTED);
    return;
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
        uv_tcp_close_reset(&c->inet_tcp.tcp, NULL);
    }
    uv_close((uv_handle_t *) &c->timer_reconnect, NULL);
    if (c->keepalive_interval) {
        uv_close((uv_handle_t *) &c->timer_keepalive, NULL);
    }
}

int
tcp_client_send(tcp_client_t *c, buffer_t *buf) {
    int rc = tcp_send(&c->inet_tcp.stream, buf, c->cipher_e);
    if (rc) {
        tcp_client_close(c);
    }
    return rc;
}

int tcp_client_connected(tcp_client_t *c) {
    return ATOM_LOAD(&c->status) == CONNECTED;
}

int tcp_client_disconnected(tcp_client_t *c) {
    return ATOM_LOAD(&c->status) == DISCONNECTED;
}
