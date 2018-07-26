#include <string.h>
#include <assert.h>

#include "uv.h"

#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "util.h"
#include "peer.h"
#include "tun.h"
#include "tcp.h"


typedef struct {
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } handle;
    struct sockaddr addr;
    buffer_t recv_buffer;
    packet_t packet;
    cipher_ctx_t *cipher_e;
    cipher_ctx_t *cipher_d;
    peer_t *peer;
} client_t;

typedef struct tcp_server {
    struct sockaddr *addr;
    int inet_tcp_fd;
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } inet_tcp;
    tundev_ctx_t *tun_ctx;
} tcp_server_t;

static client_t *
client_new(size_t mtu) {
    client_t *c = malloc(sizeof(*c));
    memset(c, 0, sizeof(*c));
    buffer_alloc(&c->recv_buffer, mtu + CRYPTO_MAX_OVERHEAD);
    packet_reset(&c->packet);
    c->cipher_e = cipher_new();
    c->cipher_d = cipher_new();
    return c;
}

static void
client_free(client_t *c) {
    cipher_free(c->cipher_e);
    cipher_free(c->cipher_d);
    buffer_free(&c->recv_buffer);
    free(c);
}

static void
client_close_cb(uv_handle_t *handle) {
    client_t *client = container_of(handle, client_t, handle);
    client_free(client);
}

static void
client_close(client_t *c) {
    if (c->peer) {
        c->peer->data = NULL;
        c->peer = NULL;
    }
    uv_close(&c->handle.handle, client_close_cb);
}

tcp_server_t *
tcp_server_new(tundev_ctx_t *ctx, struct sockaddr *addr) {
    tcp_server_t *s = malloc(sizeof *s);
    memset(s, 0, sizeof *s);
    s->addr = addr;
    s->tun_ctx = ctx;
    return s;
}

void
tcp_server_free(tcp_server_t *s) {
    free(s);
}

static void
handle_invalid_packet(client_t *client) {
    int port = 0;
    char remote[INET_ADDRSTRLEN + 1];
    port = ip_name(&client->addr, remote, sizeof(remote));
    logger_log(LOG_ERR, "Invalid tcp packet from %s:%d", remote, port);
    client_close(client);
}

static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    client_t *client = container_of(handle, client_t, handle);
    buf->base = (char *)client->recv_buffer.data + client->recv_buffer.len;
    buf->len = client->recv_buffer.capacity - client->recv_buffer.len;
    assert(buf->len > 0);
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tundev_ctx_t *ctx;
    client_t *client;

    ctx = stream->data;
    client = container_of(stream, client_t, handle.stream);

    if (nread > 0) {
        client->recv_buffer.len += nread;
        for (;;) {
            int rc = packet_parse(&client->packet, &client->recv_buffer, client->cipher_d);
            if (rc == PACKET_UNCOMPLETE) {
                return;
            } else if (rc == PACKET_INVALID) {
                goto error;
            }

            struct iphdr *iphdr = (struct iphdr *) client->packet.buf;

            in_addr_t client_network = iphdr->saddr & htonl(ctx->tun->netmask);
            if (client_network != ctx->tun->network) {
                char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
                logger_log(LOG_ERR, "Invalid peer: %s", a);
                client_close(client);
                return;
            }

            if (client->peer == NULL) {
                uv_rwlock_rdlock(&rwlock);
                peer_t *peer = peer_lookup(iphdr->saddr, peers);
                uv_rwlock_rdunlock(&rwlock);
                if (peer == NULL) {
                    char saddr[24] = {0}, daddr[24] = {0};
                    parse_addr(iphdr, saddr, daddr);
                    logger_log(LOG_NOTICE, "[TCP] Cache miss: %s -> %s",
                               saddr, daddr);

                    uv_rwlock_wrlock(&rwlock);
                    peer = peer_add(iphdr->saddr, &client->addr, peers);
                    uv_rwlock_wrunlock(&rwlock);

                } else {
                    if (peer->data) {
                        client_t *old = peer->data;
                        client_close(old);
                    }
                }

                peer->protocol= xTUN_TCP;
                peer->data = client;
                client->peer = peer;
            }

            buffer_t tmp = {
                .data = client->packet.buf,
                .len = client->packet.size
            };
            if (packet_is_keepalive(&tmp) != 1) { // keepalive
                tun_write(ctx->tunfd, client->packet.buf, client->packet.size);
            }

            int remain = client->recv_buffer.len - client->recv_buffer.off;
            assert(remain >= 0);
            if (remain > 0) {
                memmove(client->recv_buffer.data,
                        client->recv_buffer.data + client->recv_buffer.off, remain);
            }
            client->recv_buffer.len = remain;
            client->recv_buffer.off = 0;
            packet_reset(&client->packet);
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "Receive from client failed (%d: %s)",
                       nread, uv_strerror(nread));
        }
        client_close(client);
    }

    return;

error:
    if (verbose) {
        dump_hex(client->recv_buffer.data, client->recv_buffer.len, "Invalid tcp Packet");
    }
    handle_invalid_packet(client);
}

static void
client_info(client_t *client) {
    int port = 0;
    char remote[INET_ADDRSTRLEN + 1];
    port = ip_name(&client->addr, remote, sizeof(remote));
    logger_log(LOG_INFO, "%s:%d incoming", remote, port);
}

static void
accept_cb(uv_stream_t *stream, int status) {
    tundev_ctx_t *ctx = stream->data;
    client_t *client = client_new(ctx->tun->mtu);

    // TODO: Store client
    uv_tcp_init(stream->loop, &client->handle.tcp);
    int rc = uv_accept(stream, &client->handle.stream);
    if (rc == 0) {
        int len = sizeof(struct sockaddr);
        uv_tcp_getpeername(&client->handle.tcp, &client->addr, &len);
        client_info(client);
        client->handle.stream.data = ctx;
        uv_tcp_nodelay(&client->handle.tcp, 1);
        uv_tcp_keepalive(&client->handle.tcp, 1, 60);
        uv_read_start(&client->handle.stream, alloc_cb, recv_cb);
        // TODO: register client handler

    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        client_close(client);
    }
}

int
tcp_server_start(tcp_server_t *s, uv_loop_t *loop) {
    int rc;

    uv_tcp_init(loop, &s->inet_tcp.tcp);

    s->inet_tcp_fd = create_socket(SOCK_STREAM, 1);
    if (s->inet_tcp_fd < 0) {
        logger_stderr("create socket error (%d: %s)", errno, strerror(errno));
        exit(1);
    }
    if ((rc = uv_tcp_open(&s->inet_tcp.tcp, s->inet_tcp_fd))) {
        logger_stderr("tcp open error (%d: %s)", rc, uv_strerror(rc));
        exit(1);
    }

    uv_tcp_bind(&s->inet_tcp.tcp, s->addr, 0);
    if (rc) {
        logger_stderr("tcp bind error (%d: %s)", rc, uv_strerror(rc));
        exit(1);
    }

    s->inet_tcp.tcp.data = s->tun_ctx;
    rc = uv_listen(&s->inet_tcp.stream, 128, accept_cb);
    if (rc) {
        logger_stderr("tcp listen error (%d: %s)", rc, uv_strerror(rc));
        exit(1);
    }
    return rc;
}

void
tcp_server_stop(tcp_server_t *s) {
    if (uv_is_active(&s->inet_tcp.handle)) {
        uv_close(&s->inet_tcp.handle, NULL);
    }
    // TODO: Close all client
}

void
tcp_server_send(peer_t *peer, buffer_t *buf) {
    client_t *client = peer->data;
    if (client) {
        tcp_send(&client->handle.stream, buf, client->cipher_e);
    } else {
        buffer_free(buf);
    }
}
