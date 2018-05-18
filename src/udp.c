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

#include "util.h"
#include "logger.h"
#include "common.h"
#include "crypto.h"
#include "peer.h"
#include "tun.h"
#ifdef ANDROID
#include "android.h"
#endif


static void
inet_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              inet_udp);
    buf->base = (char *) ctx->network_buffer;
    buf->len = ctx->tun->mtu + PRIMITIVE_BYTES;
}

static void
inet_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
             const struct sockaddr *addr, unsigned flags)
{
    if (nread <= 0) {
        return;
    }

    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              inet_udp);

    uint8_t *m = (uint8_t *)buf->base;
    ssize_t mlen = nread - PRIMITIVE_BYTES;

    int valid = mlen > 0 && mlen <= ctx->tun->mtu;
    if (!valid) {
        goto error;
    }

    int rc = crypto_decrypt(m, (uint8_t *)buf->base, nread);
    if (rc) {
        goto error;
    }

    if (mode == xTUN_SERVER) {
        struct iphdr *iphdr = (struct iphdr *) m;

        in_addr_t client_network = iphdr->saddr & htonl(ctx->tun->netmask);
        if (client_network != ctx->tun->network) {
            char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            return logger_log(LOG_ERR, "Invalid client: %s", a);
        }

        // TODO: Compare source address
        uv_rwlock_rdlock(&rwlock);
        struct peer *peer = lookup_peer(iphdr->saddr, peers);
        uv_rwlock_rdunlock(&rwlock);
        if (peer == NULL) {
            char saddr[24] = {0}, daddr[24] = {0};
            parse_addr(iphdr, saddr, daddr);
            logger_log(LOG_NOTICE, "[UDP] Cache miss: %s -> %s",
                       saddr, daddr);
            uv_rwlock_wrlock(&rwlock);
            peer = save_peer(iphdr->saddr, (struct sockaddr *) addr, peers);
            uv_rwlock_wrunlock(&rwlock);

        } else {
            if (memcmp(&peer->remote_addr, addr, sizeof(*addr))) {
                peer->remote_addr = *addr;
            }
        }
        peer->protocol = xTUN_UDP;

        if (check_incoming_packet(m, mlen) == 1) { // keepalive
            return;
        }
    }

    return tun_write(ctx->tunfd, m, mlen);

    int port = 0;
    char remote[INET_ADDRSTRLEN + 1];
error:
    port = ip_name(addr, remote, sizeof(remote));
    logger_log(LOG_ERR, "Invalid UDP packet from %s:%d", remote, port);
    if (verbose) {
        dump_hex(buf->base, nread, "Invalid udp Packet");
    }
}

static void
inet_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "UDP send failed (%s)",
                   uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *) (req + 1);
    free(buf->base);
    free(req);
}

void
udp_send(struct tundev_context *ctx, uint8_t *buf, int len, struct sockaddr *addr) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *outbuf = (uv_buf_t *) (write_req + 1);
    outbuf->base = (char *) buf;
    outbuf->len = len;
    int rc = uv_udp_send(write_req, &ctx->inet_udp, outbuf, 1, addr, inet_send_cb);
    if (rc) {
        logger_log(LOG_ERR, "UDP Write error (%s)", uv_strerror(rc));
        free(buf);
    }
}

static void
keepalive(uv_timer_t *handle) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              timer_keepalive);
    size_t len = sizeof(struct iphdr) + PRIMITIVE_BYTES + 1;
    uint8_t *buf = calloc(1, len);
    construct_keepalive_packet(ctx->tun, buf + PRIMITIVE_BYTES);
    crypto_encrypt(buf, buf + PRIMITIVE_BYTES, len - PRIMITIVE_BYTES);
    udp_send(ctx, buf, len, &ctx->tun->addr);
}

int
udp_start(struct tundev_context *ctx, uv_loop_t *loop) {
    int rc;

    ctx->network_buffer = malloc(ctx->tun->mtu + PRIMITIVE_BYTES);

    uv_udp_init(loop, &ctx->inet_udp);

    ctx->inet_udp_fd = create_socket(SOCK_DGRAM, mode == xTUN_SERVER ? 1 : 0);
    if ((rc = uv_udp_open(&ctx->inet_udp, ctx->inet_udp_fd))) {
        logger_log(LOG_ERR, "UDP open error: %s", uv_strerror(rc));
        exit(1);
    }

#ifdef ANDROID
        rc = protect_socket(ctx->inet_udp_fd);
        logger_log(rc ? LOG_INFO : LOG_ERR, "Protect socket %s",
                   rc ? "successful" : "failed");
#endif

    if (mode == xTUN_SERVER) {
        rc = uv_udp_bind(&ctx->inet_udp, &ctx->tun->addr, UV_UDP_REUSEADDR);
        if (rc) {
            logger_stderr("UDP bind error: %s", uv_strerror(rc));
            exit(1);
        }

    } else {
        if (ctx->tun->keepalive_delay) {
            uint64_t timeout = ctx->tun->keepalive_delay * 1000;
            uv_timer_init(loop, &ctx->timer_keepalive);
            uv_timer_start(&ctx->timer_keepalive, keepalive, timeout, timeout);
        }
    }

    return uv_udp_recv_start(&ctx->inet_udp, inet_alloc_cb, inet_recv_cb);
}

void
udp_stop(struct tundev_context *ctx) {
    uv_close((uv_handle_t *) &ctx->inet_udp, NULL);
    if (mode == xTUN_CLIENT) {
        if (ctx->tun->keepalive_delay) {
            uv_close((uv_handle_t *) &ctx->timer_keepalive, NULL);
        }
    }
}
