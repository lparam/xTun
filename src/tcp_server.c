#include <string.h>
#include <assert.h>

#include "uv.h"

#include "common.h"
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
    tundev_context_t *tun_ctx;
} tcp_server_t;

static client_t *
client_new() {
    client_t *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    memset(&client->recv_buffer, 0, sizeof client->recv_buffer);
    return client;
}

static void
client_free(client_t *client) {
    free(client);
}

tcp_server_t *
tcp_server_new(tundev_context_t *ctx, struct sockaddr *addr) {
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
client_close_cb(uv_handle_t *handle) {
    client_t *client = container_of(handle, client_t, handle);
    client_free(client);
}

static void
close_client(client_t *client) {
    if (client->peer) {
        client->peer->data = NULL;
        client->peer = NULL;
    }
    uv_close(&client->handle.handle, client_close_cb);
}

static void
handle_invalid_packet(client_t *client) {
    int port = 0;
    char remote[INET_ADDRSTRLEN + 1];
    port = ip_name(&client->addr, remote, sizeof(remote));
    logger_log(LOG_ERR, "Invalid tcp packet from %s:%d", remote, port);
    close_client(client);
}

static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    client_t *client = container_of(handle, client_t, handle);
    buf->base = (char *)client->recv_buffer.data + client->recv_buffer.len;
    buf->len = sizeof(client->recv_buffer.data) - client->recv_buffer.len;
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct tundev_context *ctx;
    client_t *client;

    ctx = stream->data;
    client = container_of(stream, client_t, handle.stream);

    if (nread > 0) {
        client->recv_buffer.len += nread;
        for (;;) {
            packet_t packet;
            int rc = packet_parse(&client->recv_buffer, &packet);
            if (rc == PACKET_UNCOMPLETE) {
                return;
            } else if (rc == PACKET_INVALID) {
                goto error;
            }

            int clen = packet.size;
            int mlen = packet.size - PRIMITIVE_BYTES;
            uint8_t *c = packet.buf, *m = packet.buf;

            assert(mlen > 0 && mlen <= ctx->tun->mtu);

            int err = crypto_decrypt(m, c, clen);
            if (err) {
                goto error;
            }

            struct iphdr *iphdr = (struct iphdr *) m;

            in_addr_t client_network = iphdr->saddr & htonl(ctx->tun->netmask);
            if (client_network != ctx->tun->network) {
                char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
                logger_log(LOG_ERR, "Invalid client: %s", a);
                close_client(client);
                return;
            }

            if (client->peer == NULL) {
                uv_rwlock_rdlock(&rwlock);
                peer_t *peer = lookup_peer(iphdr->saddr, peers);
                uv_rwlock_rdunlock(&rwlock);
                if (peer == NULL) {
                    char saddr[24] = {0}, daddr[24] = {0};
                    parse_addr(iphdr, saddr, daddr);
                    logger_log(LOG_NOTICE, "[TCP] Cache miss: %s -> %s",
                               saddr, daddr);

                    uv_rwlock_wrlock(&rwlock);
                    peer = save_peer(iphdr->saddr, &client->addr, peers);
                    uv_rwlock_wrunlock(&rwlock);

                } else {
                    if (peer->data) {
                        client_t *old = peer->data;
                        close_client(old);
                    }
                }

                peer->protocol= xTUN_TCP;
                peer->data = client;
                client->peer = peer;
            }

            if (is_keepalive_packet(m, mlen) != 1) { // keepalive
                tun_write(ctx->tunfd, m, mlen);
            }

            int remain = client->recv_buffer.len - client->recv_buffer.off;
            assert(remain >= 0);
            if (remain > 0) {
                memmove(client->recv_buffer.data,
                        client->recv_buffer.data + client->recv_buffer.off, remain);
            }
            client->recv_buffer.len = remain;
            client->recv_buffer.off = 0;
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "Receive from client failed (%d: %s)",
                       nread, uv_strerror(nread));
        }
        close_client(client);
    }

    return;

error:
    if (verbose) {
        dump_hex(buf->base, nread, "Invalid tcp Packet");
    }
    handle_invalid_packet(client);
}

static void
accept_cb(uv_stream_t *stream, int status) {
    struct tundev_context *ctx = stream->data;
    client_t *client = client_new();

    // TODO: Store client
    uv_tcp_init(stream->loop, &client->handle.tcp);
    int rc = uv_accept(stream, &client->handle.stream);
    if (rc == 0) {
        int len = sizeof(struct sockaddr);
        uv_tcp_getpeername(&client->handle.tcp, &client->addr, &len);
        client->handle.stream.data = ctx;
        uv_tcp_nodelay(&client->handle.tcp, 1);
        uv_tcp_keepalive(&client->handle.tcp, 1, 60);
        uv_read_start(&client->handle.stream, alloc_cb, recv_cb);
        // TODO: register client handler

    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_client(client);
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
tcp_server_send(peer_t *peer, uint8_t *buf, int len) {
    client_t *client = peer->data;
    if (client) {
        tcp_send(&client->handle.stream, buf, len);
    } else {
        free(buf);
    }
}
