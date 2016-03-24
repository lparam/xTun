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
#include "client.h"
#include "tun.h"
#include "tun_imp.h"


struct client_context {
    union {
        uv_tcp_t tcp;
        uv_handle_t handle;
        uv_stream_t stream;
    } handle;
    struct packet *packet;
    /* struct peer *peer; */
};


struct client_context *
new_client() {
    struct client_context *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    return client;
}

static void
free_client(struct client_context *client) {
    free(client);
}

static void
client_close_cb(uv_handle_t *handle) {
    struct client_context *client = (struct client_context *) handle->data;
    free_client(client);
}

void
close_client(struct client_context *client) {
    client->handle.handle.data = client;
    uv_close(&client->handle.handle, client_close_cb);
}

static void
alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct client_context *client = container_of(handle, struct client_context,
                                                 handle.handle);
    struct packet *packet = client->packet;
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
    struct client_context *client = req->data;
    if (status) {
        char buf[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t port = ip_name(&client->remote_addr, addrbuf, sizeof(buf));
        logger_log(LOG_ERR, "send to %s:%d failed: %s", buf, port,
                   uv_strerror(status));
    }
    free(req);
}

static void
parse_addr(struct iphdr *iphdr, char *saddr, char *daddr) {
    char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
    strcpy(saddr, a);
    a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
    strcpy(daddr, a);
}

static void
recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client_context *client = container_of(stream, struct client_context,
                                                 handle.stream);
    if (nread > 0) {
        struct packet *packet = client->packet;
        int rc = packet_filter(packet, buf->base, nread);
        if (rc == PACKET_UNCOMPLETE) {
            return;
        } else if (rc == PACKET_INVALID) {
            goto error;
        }

        int clen = packet->size;
        int mlen = packet->size - PRIMITIVE_BYTES;
        uint8_t *c = packet->buf, *m = packet->buf;

        int err = crypto_decrypt(m, c, clen);
        if (err) {
            goto error;
        }

        struct iphdr *iphdr = (struct iphdr *) m;

        if (verbose) {
            char saddr[24] = {0}, daddr[24] = {0};
            parse_addr(iphdr, saddr, daddr);
            logger_log(LOG_DEBUG, "Received %ld bytes from %s to %s",
                       mlen, saddr, daddr);
        }

        /* TODO: save client info */
        uv_rwlock_rdlock(&rwlock);
        struct peer *peer = lookup_peer(iphdr->saddr, tun->peers);
        uv_rwlock_rdunlock(&rwlock);
        if (peer == NULL) {
            char saddr[24] = {0}, daddr[24] = {0};
            parse_addr(iphdr, saddr, daddr);
            logger_log(LOG_WARNING, "Cache miss: %s -> %s", saddr, daddr);
            uv_rwlock_wrlock(&rwlock);
            peer = save_peer(iphdr->saddr, addr, tun->raddrs);
            uv_rwlock_wrunlock(&rwlock);

        } else {
            if (memcmp(&peer->remote_addr, addr, sizeof(*addr))) {
                peer->remote_addr = *addr;
            }
        }

        struct tundev_context *ctx = stream->data;
        network_to_tun(ctx->tunfd, m, mlen);

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            char buf[INET6_ADDRSTRLEN + 1] = {0};
            uint16_t port = ip_name(&client->remote_addr, buf, sizeof(buf));
            logger_log(LOG_ERR, "Receive from %s:%d failed: %s", buf, port,
                       uv_strerror(nread));
        }
        close_client(client);
    }

    return;

error:
    logger_log(LOG_ERR, "invalid tcp packet");
    close_client(client);
}

static void
receive_from_client(struct client_context *client) {
    packet_reset(client->packet);
    uv_read_start(&client->handle.stream, alloc_cb, recv_cb);
}

static void
accept_cb(uv_stream_t *stream, int status) {
    struct tundev_context *ctx = stream->data;
    struct client_context *client = new_client();

    uv_tcp_init(stream->loop, &client->handle.tcp);
    int rc = uv_accept(stream, &client->handle.stream);
    if (rc == 0) {
        int len = sizeof(client->remote_addr);
        uv_tcp_getpeername(&client->handle.tcp, &client->remote_addr, &len);
        client->handle.stream.data = ctx;
        receive_from_client(client);
    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_client(client);
    }
}

int
tcp_start(struct tundev *tun, uv_loop_t *loop) {
    struct tundev_context *ctx = tun->contexts;

    uv_tcp_init(loop, &ctx->inet_tcp.tcp);
    int rc = uv_tcp_bind(&ctx->inet_tcp.tcp, &tun->bind_addr, 0);
    if (rc) {
        logger_stderr("tcp bind error: %s", uv_strerror(rc));
        return 1;
    }
    ctx->inet_tcp.tcp.data = ctx;
    return uv_listen(&ctx->inet_tcp.stream, 128, accept_cb);
}

void
tun_to_tcp(struct tundev_context *ctx, uint8_t *buf, int buflen) {
    buf -= HEADER_BYTES;
    write_size(buf, buflen);
    buflen += HEADER_BYTES;
    uv_buf_t data = uv_buf_init((char *) buf, buflen);
    uv_write_t *write_req = malloc(sizeof *write_req);
    write_req->data = ctx;
    uv_write(write_req, &ctx->inet_tcp.stream, &data, 1, send_cb);
}
