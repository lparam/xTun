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

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "tun.h"
#ifdef ANDROID
#include "android.h"
#endif


typedef struct udp {
    struct sockaddr *addr;
    int keepalive_interval;
    int inet_udp_fd;
    uv_udp_t inet_udp;
    uv_timer_t timer_keepalive;
    buffer_t recv_buffer;
    cipher_ctx_t *cipher;
    tundev_ctx_t *tun_ctx;
} udp_t;

udp_t *
udp_new(tundev_ctx_t *ctx, struct sockaddr *addr) {
    udp_t *udp = malloc(sizeof *udp);
    memset(udp, 0, sizeof *udp);
    udp->cipher = cipher_new();
    buffer_alloc(&udp->recv_buffer, ctx->tun->mtu + CRYPTO_MAX_OVERHEAD);
    udp->addr = addr;
    udp->tun_ctx = ctx;
    udp->keepalive_interval = ctx->tun->keepalive_interval;
    return udp;
}

void
udp_free(udp_t *udp) {
    cipher_free(udp->cipher);
    buffer_free(&udp->recv_buffer);
    free(udp);
}

static void
inet_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    udp_t *udp = container_of(handle, udp_t, inet_udp);
    buf->base = (char *)udp->recv_buffer.data;
    buf->len = udp->recv_buffer.capacity;
}

static void
inet_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
             const struct sockaddr *addr, unsigned flags)
{
    if (nread <= 0) {
        if (nread < 0) {
            logger_log(LOG_ERR, "[UDP] Receive failed (%d: %s)",
                       nread, uv_strerror(nread));
        }
        return;
    }

    char remote[INET_ADDRSTRLEN + 1];
    if (nread <= CRYPTO_UDP_MIN_OVERHEAD) {
        int port = ip_name(addr, remote, sizeof(remote));
        logger_log(LOG_ERR, "Invalid UDP packet from %s:%d", remote, port);
        return;
    }

    udp_t *udp = container_of(handle, udp_t, inet_udp);
    udp->recv_buffer.len = nread;
    int rc = crypto_decrypt_with_new_salt(&udp->recv_buffer, udp->cipher);
    if (rc) {
        int port = ip_name(addr, remote, sizeof(remote));
        logger_log(LOG_ERR, "Invalid UDP packet from %s:%d", remote, port);
        if (verbose) {
            dump_hex(udp->recv_buffer.data, udp->recv_buffer.len, "Invalid UDP Packet");
        }
        return;
    }

    if (mode == xTUN_SERVER) {
        struct iphdr *iphdr = (struct iphdr *) udp->recv_buffer.data;

        in_addr_t client_network = iphdr->saddr & htonl(udp->tun_ctx->tun->netmask);
        if (client_network != udp->tun_ctx->tun->network) {
            char *pa = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            return logger_log(LOG_ERR, "Invalid peer: %s", pa);
        }

        rwlock_rlock(&peers_rwlock);
        peer_t *peer = peer_lookup(iphdr->saddr, peers);
        rwlock_runlock(&peers_rwlock);
        if (peer == NULL) {
            char saddr[24] = {0}, daddr[24] = {0};
            parse_addr(iphdr, saddr, daddr);
            logger_log(LOG_NOTICE, "[UDP] Cache miss: %s -> %s", saddr, daddr);
            rwlock_wlock(&peers_rwlock);
            peer = peer_add(iphdr->saddr, (struct sockaddr *) addr, peers);
            rwlock_wunlock(&peers_rwlock);

        } else {
            if (memcmp(&peer->remote_addr, addr, sizeof(*addr))) {
                peer->remote_addr = *addr;
            }
        }
        peer->protocol = xTUN_UDP;

        if (packet_is_keepalive(&udp->recv_buffer)) {
            return;
        }
    }

    tun_write(udp->tun_ctx->tunfd, udp->recv_buffer.data, udp->recv_buffer.len);
}

static void
inet_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "UDP send failed (%d: %s)",
                   status, uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *) (req + 1);
    buffer_t *data = container_of(&buf->base, buffer_t, data);
    buffer_free(data);
    free(req);
}

void
udp_send(udp_t *udp, buffer_t *buf, struct sockaddr *addr) {
    crypto_encrypt_with_new_salt(buf, udp->cipher);
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *outbuf = (uv_buf_t *) (write_req + 1);
    outbuf->base = (char *) buf->data;
    outbuf->len = buf->len;
    int rc = uv_udp_send(write_req, &udp->inet_udp, outbuf, 1,
                         mode == xTUN_SERVER ? addr : udp->addr, inet_send_cb);
    if (rc) {
        logger_log(LOG_ERR, "UDP Write error (%d: %s)", rc, uv_strerror(rc));
        buffer_free(buf);
        free(write_req);
    }
}

static void
keepalive(uv_timer_t *handle) {
    udp_t *udp = container_of(handle, udp_t, timer_keepalive);
    buffer_t buf;
    packet_construct_keepalive(&buf, udp->tun_ctx->tun);
    udp_send(udp, &buf, NULL);
}

int
udp_start(udp_t *udp, uv_loop_t *loop) {
    int rc;

    uv_udp_init(loop, &udp->inet_udp);

    udp->inet_udp_fd = create_socket(SOCK_DGRAM, mode == xTUN_SERVER ? 1 : 0);
    if (udp->inet_udp_fd < 0) {
        logger_stderr("create socket error: %s", strerror(errno));
        exit(1);
    }
    socket_mark(udp->inet_udp_fd, nf_mark);
    if ((rc = uv_udp_open(&udp->inet_udp, udp->inet_udp_fd))) {
        logger_log(LOG_ERR, "UDP open error: %s", uv_strerror(rc));
        exit(1);
    }

#ifdef ANDROID
        extern int protect_socket(int fd);
        rc = protect_socket(udp->inet_udp_fd);
        logger_log(rc ? LOG_INFO : LOG_ERR, "Protect socket %s",
                   rc ? "successful" : "failed");
#endif

    if (mode == xTUN_SERVER) {
        rc = uv_udp_bind(&udp->inet_udp, udp->addr, UV_UDP_REUSEADDR);
        if (rc) {
            logger_stderr("UDP bind error: %s", uv_strerror(rc));
            exit(1);
        }

    } else {
        if (udp->keepalive_interval) {
            uint64_t timeout = udp->keepalive_interval * 1000;
            uv_timer_init(loop, &udp->timer_keepalive);
            uv_timer_start(&udp->timer_keepalive, keepalive, timeout, timeout);
        }
    }

    return uv_udp_recv_start(&udp->inet_udp, inet_alloc_cb, inet_recv_cb);
}

void
udp_stop(udp_t *udp) {
    uv_close((uv_handle_t *) &udp->inet_udp, NULL);
    if (mode == xTUN_CLIENT) {
        if (udp->keepalive_interval) {
            uv_close((uv_handle_t *) &udp->timer_keepalive, NULL);
        }
    }
}
