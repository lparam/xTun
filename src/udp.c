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
#include "crypto.h"
#include "peer.h"
#include "tun.h"
#include "tun_imp.h"


#define HASHSIZE 256

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
    if (nread > 0) {
        uint8_t *m = (uint8_t *)buf->base;
        ssize_t mlen = nread - PRIMITIVE_BYTES;

        int rc = crypto_decrypt(m, (uint8_t *)buf->base, nread);
        if (rc) {
            logger_log(LOG_ERR, "Invalid packet");
            return;
        }

        if (verbose) {
            char saddr[24] = {0}, daddr[24] = {0};
            struct iphdr *iphdr = (struct iphdr *) m;
            char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            strcpy(saddr, a);
            a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
            strcpy(daddr, a);
            logger_log(LOG_DEBUG, "Received %ld bytes from %s to %s",
                       mlen, saddr, daddr);
        }

        struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                                  inet_udp);

#ifdef XTUND
        struct iphdr *iphdr = (struct iphdr *) m;
        // TODO: Compare source address
        uv_rwlock_rdlock(&rwlock);
        struct peer *ra = lookup_peer(iphdr->saddr, peers);
        uv_rwlock_rdunlock(&rwlock);
        if (ra == NULL) {
            char saddr[24] = {0}, daddr[24] = {0};
            parse_addr(iphdr, saddr, daddr);
            logger_log(LOG_WARNING, "Cache miss: %s -> %s", saddr, daddr);
            uv_rwlock_wrlock(&rwlock);
            save_peer(iphdr->saddr, (struct sockaddr *) addr, peers);
            uv_rwlock_wrunlock(&rwlock);

        } else {
            if (memcmp(&ra->remote_addr, addr, sizeof(*addr))) {
                ra->remote_addr = *addr;
            }
        }
#endif

        network_to_tun(ctx->tunfd, m, mlen);
    }
}

static void
inet_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "[UDP] Tun to network failed: %s",
                   uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *) (req + 1);
    free(buf->base);
    free(req);
}

void
tun_to_udp(struct tundev_context *ctx, uint8_t *buf, int len,
           struct sockaddr *addr) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *outbuf = (uv_buf_t *) (write_req + 1);
    outbuf->base = (char *) buf;
    outbuf->len = len;
    if (write_req) {
        write_req->data = ctx;
        uv_udp_send(write_req, &ctx->inet_udp, outbuf, 1, addr, inet_send_cb);
    } else {
        free(buf);
    }
}

int
udp_start(struct tundev_context *ctx, uv_loop_t *loop) {
    uv_udp_init(loop, &ctx->inet_udp);

#ifdef XTUND
    int rc = uv_udp_bind(&ctx->inet_udp, &ctx->tun->addr, UV_UDP_REUSEADDR);
    if (rc) {
        logger_stderr("bind error: %s", uv_strerror(rc));
        return 1;
    }
#endif

    return uv_udp_recv_start(&ctx->inet_udp, inet_alloc_cb, inet_recv_cb);
}
