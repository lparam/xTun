#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "uv.h"
#include "uv/tree.h"

#include "crypto.h"
#include "logger.h"
#include "packet.h"
#include "util.h"
#include "peer.h"
#include "tun.h"
#include "tcp.h"


typedef struct client {
    uint64_t cid;
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
    RB_ENTRY(client) entry;
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

RB_HEAD(client_tree, client);

static struct client_tree clients = RB_INITIALIZER(clients);
static uint64_t gcid;

static int
client_compare(const struct client *a, const struct client *b) {
    if (a->cid < b->cid) return -1;
    if (a->cid > b->cid) return 1;
    return 0;
}

RB_GENERATE_STATIC(client_tree, client, entry, client_compare)

static client_t *
client_new(size_t mtu) {
    client_t *c = malloc(sizeof(*c));
    memset(c, 0, sizeof(*c));
    c->cid = ATOMIC_INC(&gcid);
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
    uv_rwlock_wrlock(&clients_rwlock);
    RB_REMOVE(client_tree, &clients, c);
    uv_rwlock_wrunlock(&clients_rwlock);
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
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    client_t *c = container_of(handle, client_t, handle);
    buf->base = (char *)c->recv_buffer.data + c->recv_buffer.len;
    buf->len = c->recv_buffer.capacity - c->recv_buffer.len;
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    int port;
    char remote[INET_ADDRSTRLEN + 1];
    tundev_ctx_t *ctx = stream->data;
    client_t *c = container_of(stream, client_t, handle.stream);

    if (nread <= 0) {
        if (nread < 0) {
            port = ip_name(&c->addr, remote, sizeof(remote));
            if (nread != UV_EOF) {
                logger_log(LOG_ERR, "Receive from cid:%"PRIu64" - %s:%d (%d: %s)",
                           c->cid, remote, port, nread, uv_strerror(nread));
            } else {
                logger_log(LOG_INFO, "cid:%"PRIu64" - %s:%d close",
                           c->cid, remote, port);
            }
            client_close(c);
        }
        return;
    }

    c->recv_buffer.len += nread;
    for (;;) {
        int rc = packet_parse(&c->packet, &c->recv_buffer, c->cipher_d);
        if (rc == PACKET_UNCOMPLETE) {
            break;
        } else if (rc == PACKET_INVALID) {
            port = ip_name(&c->addr, remote, sizeof(remote));
            logger_log(LOG_ERR, "Invalid tcp packet from cid:%"PRIu64" - %s:%d",
                       c->cid, remote, port);
            if (verbose) {
                dump_hex(c->recv_buffer.data, c->recv_buffer.len,
                         "Invalid tcp Packet");
            }
            client_close(c);
            break;
        }

        struct iphdr *iphdr = (struct iphdr *) c->packet.buf;

        in_addr_t client_network = iphdr->saddr & htonl(ctx->tun->netmask);
        if (client_network != ctx->tun->network) {
            char *pa = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            logger_log(LOG_ERR, "Invalid peer: %s", pa);
            client_close(c);
            break;
        }

        if (c->peer == NULL) {
            rwlock_rlock(&peers_rwlock);
            peer_t *peer = peer_lookup(iphdr->saddr, peers);
            rwlock_runlock(&peers_rwlock);
            if (peer == NULL) {
                char saddr[24] = {0}, daddr[24] = {0};
                parse_addr(iphdr, saddr, daddr);
                logger_log(LOG_NOTICE, "[TCP] Cache miss: %s -> %s", saddr, daddr);
                rwlock_wlock(&peers_rwlock);
                peer = peer_add(iphdr->saddr, &c->addr, peers);
                rwlock_wunlock(&peers_rwlock);

            } else {
                if (peer->data) {
                    client_t *old = peer->data;
                    client_close(old);
                }
            }

            peer->protocol= xTUN_TCP;
            peer->data = c;
            c->peer = peer;
        }

        buffer_t tmp = {
            .data = c->packet.buf,
            .len = c->packet.size
        };
        if (!packet_is_keepalive(&tmp)) {
            tun_write(ctx->tunfd, c->packet.buf, c->packet.size);
        }

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
client_info(client_t *client) {
    int port = 0;
    char remote[INET_ADDRSTRLEN + 1];
    port = ip_name(&client->addr, remote, sizeof(remote));
    logger_log(LOG_INFO, "cid:%"PRIu64" - Connection attempt from [%s:%d]",
               client->cid, remote, port);
}

static void
accept_cb(uv_stream_t *stream, int status) {
    tundev_ctx_t *ctx = stream->data;
    client_t *client = client_new(ctx->tun->mtu);
    uv_rwlock_wrlock(&clients_rwlock);
    RB_INSERT(client_tree, &clients, client);
    uv_rwlock_wrunlock(&clients_rwlock);

    uv_tcp_init(stream->loop, &client->handle.tcp);
    int rc = uv_accept(stream, &client->handle.stream);
    if (rc == 0) {
        int len = sizeof(struct sockaddr);
        uv_tcp_getpeername(&client->handle.tcp, &client->addr, &len);
        client_info(client);
        client->handle.stream.data = ctx;
        int fd = client->handle.tcp.io_watcher.fd;
        if (tcp_opts(fd) != 0) {
            logger_stderr("set tcp opts - %s", strerror(errno));
        }
        uv_read_start(&client->handle.stream, alloc_cb, recv_cb);

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

    if ((rc = uv_tcp_bind(&s->inet_tcp.tcp, s->addr, 0))) {
        logger_stderr("tcp bind error (%d: %s)", rc, uv_strerror(rc));
        exit(1);
    }

    if ((rc = uv_tcp_simultaneous_accepts(&s->inet_tcp.tcp, 1))) {
        logger_stderr("tcp simultaneous accept (%d: %s)", rc, uv_strerror(rc));
        exit(1);
    }

    s->inet_tcp.tcp.data = s->tun_ctx;
    rc = uv_listen(&s->inet_tcp.stream, SOMAXCONN, accept_cb);
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
    client_t *c;
    RB_FOREACH(c, client_tree, &clients) {
        client_close(c);
    }
}

void
tcp_server_send(peer_t *peer, buffer_t *buf) {
    client_t *client = peer->data;
    if (client) {
        int rc = tcp_send(&client->handle.stream, buf, client->cipher_e);
        if (rc) {
            client_close(client);
        }
    } else {
        buffer_free(buf);
    }
}
