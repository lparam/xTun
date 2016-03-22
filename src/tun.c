#define _GNU_SOURCE
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
#include "tun.h"
#ifdef ANDROID
#include "android.h"
#endif


#define HASHSIZE 256


struct raddr {
    struct in_addr     tun_addr;
	struct sockaddr    remote_addr;
	struct raddr      *next;
};

struct tundev_context {
	int              tunfd;
    int              inet_fd;
    uint8_t         *network_buffer;
    uv_udp_t         inet;
    uv_poll_t        watcher;
    uv_sem_t         semaphore;
    uv_async_t       async_handle;
    struct tundev   *tun;
};

struct tundev {
    char                    iface[128];
    char                    ifconf[128];
    int                     mode;
    int                     mtu;
    struct sockaddr         bind_addr;
    struct sockaddr         server_addr;
#ifdef ANDROID
    int                     is_global_proxy;
    struct sockaddr         dns_server;
#endif
    struct raddr           *raddrs[HASHSIZE];
    uint32_t                queues;
    struct tundev_context   contexts[0];
};

struct signal_ctx {
    int            signum;
    uv_signal_t    sig;
} signals[2];

static uv_rwlock_t rwlock;

static void loop_close(uv_loop_t *loop);
static void signal_cb(uv_signal_t *handle, int signum);
static void signal_install(uv_loop_t *loop, uv_signal_cb cb, void *data);


static uint32_t
hash_addr(uint32_t addr) {
	uint32_t a = addr >> 24;
	uint32_t b = addr >> 12;
	uint32_t c = addr;
	return (a + b + c) % HASHSIZE;
}

static struct raddr *
lookup_addr(uint32_t addr, struct raddr **raddrs) {
	int h = hash_addr(addr);
	struct raddr *ra = raddrs[h];
	if (ra == NULL)
		return NULL;
	if (ra->tun_addr.s_addr == addr)
		return ra;
	struct raddr *last = ra;
	while (last->next) {
		ra = last->next;
        if (ra->tun_addr.s_addr == addr) {
			return ra;
		}
		last = ra;
	}
	return NULL;
}

static void
save_addr(uint32_t tun_addr, const struct sockaddr *remote_addr,
          struct raddr **raddrs) {
	int h = hash_addr(tun_addr);
	struct raddr *ra = malloc(sizeof(struct raddr));
	memset(ra, 0, sizeof(*ra));
    ra->tun_addr.s_addr = tun_addr;
    ra->remote_addr = *remote_addr;
	ra->next = raddrs[h];
	raddrs[h] = ra;
}

#ifndef ANDROID
static void
clear_addrs(struct raddr **addrs) {
	for (int i = 0; i < HASHSIZE; i++) {
        struct raddr *ra = addrs[i];
        while (ra) {
            void *tmp = ra;
            ra = ra->next;
            free(tmp);
        }
		addrs[i] = NULL;
	}
}
#endif

static void
inet_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct tundev_context *ctx =
            container_of(handle, struct tundev_context, inet);
    buf->base = (char *)ctx->network_buffer;
    buf->len = ctx->tun->mtu + PRIMITIVE_BYTES;
}

void
network_to_tun(int tunfd, uint8_t *buf, ssize_t len) {
    uint8_t *pos = buf;
    size_t remaining = len;
    while(remaining) {
        ssize_t sz = write(tunfd, pos, remaining);
        if(sz == -1) {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            } else {
                continue;
            }
        }
        pos += sz;
        remaining -= sz;
    }
}

static void
inet_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
             const struct sockaddr *addr, unsigned flags) {
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

        struct tundev_context *ctx = container_of(handle,
                                                  struct tundev_context, inet);
        struct tundev *tun = ctx->tun;
        struct iphdr *iphdr = (struct iphdr *) m;

        if (tun->mode == TUN_MODE_SERVER) {
            // TODO: Compare source address
            uv_rwlock_rdlock(&rwlock);
            struct raddr *ra = lookup_addr(iphdr->saddr, tun->raddrs);
            uv_rwlock_rdunlock(&rwlock);
            if (ra == NULL) {
                char saddr[24] = {0}, daddr[24] = {0};
                char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
                strcpy(saddr, a);
                a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
                strcpy(daddr, a);
                logger_log(LOG_WARNING, "Cache miss: %s -> %s", saddr, daddr);
                uv_rwlock_wrlock(&rwlock);
                save_addr(iphdr->saddr, addr, tun->raddrs);
                uv_rwlock_wrunlock(&rwlock);

            } else {
                if (memcmp(&ra->remote_addr, addr, sizeof(*addr))) {
                    ra->remote_addr = *addr;
                }
            }

        } else {
#ifdef ANDROID
            /* uint16_t frag = iphdr->frag_off & htons(0x1fff);
            if ((iphdr->protocol == IPPROTO_UDP) && (frag == 0)) {
                struct udphdr *udph =
                  (struct udphdr *) (m + sizeof(struct iphdr));
                if (ntohs(udph->source) == 53) {
                }
            } */
#endif
        }

        network_to_tun(ctx->tunfd, m, mlen);
    }
}

static void
inet_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "Tun to network failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *) (req + 1);
    free(buf->base);
    free(req);
}

static void
tun_to_network(struct tundev_context *ctx, uint8_t *buf, int len,
               struct sockaddr *addr) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *outbuf = (uv_buf_t *) (write_req + 1);
    outbuf->base = (char *) buf;
    outbuf->len = len;
    if (write_req) {
        write_req->data = ctx;
        uv_udp_send(write_req, &ctx->inet, outbuf, 1, addr, inet_send_cb);
    } else {
        free(buf);
    }
}

static void
poll_cb(uv_poll_t *watcher, int status, int events) {
    if (events == UV_READABLE) {
        struct sockaddr *addr;
        struct tundev *tun;
        struct tundev_context *ctx;
        uint8_t *tunbuf, *m;

        ctx = container_of(watcher, struct tundev_context, watcher);
        tun = ctx->tun;

        tunbuf = malloc(PRIMITIVE_BYTES + tun->mtu);
        m = tunbuf + PRIMITIVE_BYTES;

        int mlen = read(ctx->tunfd, m, tun->mtu);
        if (mlen <= 0) {
            free(tunbuf);
            return;
        }

        struct iphdr *iphdr = (struct iphdr *)m;

        if (tun->mode == TUN_MODE_SERVER) {
            uv_rwlock_rdlock(&rwlock);
            struct raddr *ra = lookup_addr(iphdr->daddr, tun->raddrs);
            uv_rwlock_rdunlock(&rwlock);
            if (ra == NULL) {
                char saddr[24] = {0}, daddr[24] = {0};
                char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
                strcpy(saddr, a);
                a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
                strcpy(daddr, a);
                logger_log(LOG_ERR, "Destination address miss: %s -> %s",
                           saddr, daddr);
                free(tunbuf);
                return;
            }
            addr = &ra->remote_addr;

        } else {
#ifdef ANDROID
            if (!tun->is_global_proxy) {
                uint16_t frag = iphdr->frag_off & htons(0x1fff);
                if ((iphdr->protocol == IPPROTO_UDP) && (frag == 0)) {
                    struct udphdr *udph =
                          (struct udphdr *) (m + sizeof(struct iphdr));
                    if (ntohs(udph->dest) == 53) {
                        int rc = handle_local_dns_query(ctx->tunfd,
                                      &tun->dns_server, m, mlen);
                        if (rc) {
                            return;
                        }
                    }
                }
            }
#endif
            addr = &tun->server_addr;
        }

        if (verbose) {
            char saddr[24] = {0}, daddr[24] = {0};
            char *addr = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            strcpy(saddr, addr);
            addr = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
            strcpy(daddr, addr);
            logger_log(LOG_DEBUG, "Sending %ld bytes from %s to %s",
                       mlen, saddr, daddr);
        }

        crypto_encrypt(tunbuf, m, mlen);
        tun_to_network(ctx, tunbuf, PRIMITIVE_BYTES + mlen, addr);
    }
}

#ifndef ANDROID
struct tundev *
tun_alloc(char *iface, uint32_t parallel) {
    int i, err, fd;
    struct tundev *tun;

    size_t ctxsz = sizeof(struct tundev_context) * parallel;
    tun = malloc(sizeof(*tun) + ctxsz);
    memset(tun, 0, sizeof(*tun) + ctxsz);
    tun->queues = parallel;
    strcpy(tun->iface, iface);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, tun->iface, IFNAMSIZ);

    for (i = 0; i < parallel; i++) {
        if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 ) {
            logger_stderr("Open /dev/net/tun: %s", strerror(errno));
            goto err;
        }
        err = ioctl(fd, TUNSETIFF, (void *)&ifr);
        if (err) {
            logger_stderr("Cannot allocate TUN: %s", strerror(errno));
            close(fd);
            goto err;
        }
        struct tundev_context *ctx = &tun->contexts[i];
        ctx->tun = tun;
        ctx->tunfd = fd;
        ctx->inet_fd = create_socket(SOCK_DGRAM, 1);
    }

    return tun;
err:
    for (--i; i >= 0; i--) {
        struct tundev_context *ctx = &tun->contexts[i];
        close(ctx->tunfd);
        close(ctx->inet_fd);
    }
    free(tun);
    return NULL;
}
#else
struct tundev *
tun_alloc() {
    int queues = 1;
    size_t ctxsz = sizeof(struct tundev_context) * queues;

    struct tundev *tun = malloc(sizeof(*tun) + ctxsz);
    memset(tun, 0, sizeof(*tun) + ctxsz);
    tun->mode = TUN_MODE_CLIENT;
    tun->queues = queues;

    struct tundev_context *ctx = tun->contexts;
    ctx->tun = tun;

    return tun;
}
#endif

void
tun_free(struct tundev *tun) {
    int i;
    for (i = 0; i < tun->queues; i++) {
        free(tun->contexts[i].network_buffer);
    }
    free(tun);
}

#ifndef ANDROID
void
tun_config(struct tundev *tun, const char *ifconf, int mtu, int mode,
           struct sockaddr *addr) {
    tun->mtu = mtu;
    tun->mode = mode;
    strcpy(tun->ifconf, ifconf);

    if (mode == TUN_MODE_CLIENT) {
        tun->server_addr = *addr;
    } else {
        tun->bind_addr = *addr;
    }

	char *nmask = strchr(ifconf, '/');
	if(!nmask) {
		logger_stderr("ifconf syntax error: %s", ifconf);
		exit(0);
	}

	uint8_t ipaddr[16] = {0};
	memcpy(ipaddr, ifconf, (uint32_t) (nmask - ifconf));

	in_addr_t netmask = 0xffffffff;
	netmask = netmask << (32 - atoi(++nmask));

    int inet4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (inet4 < 0) {
		logger_stderr("Can't create tun device (udp socket): %s",
                      strerror(errno));
        exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, tun->iface, IFNAMSIZ);

	struct sockaddr_in *saddr;

    saddr = (struct sockaddr_in *)&ifr.ifr_addr;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = inet_addr((const char *)ipaddr);
	if(saddr->sin_addr.s_addr == INADDR_NONE) {
        logger_stderr("Invalid IP address: %s", ifconf);
		exit(1);
	}
    if(ioctl(inet4, SIOCSIFADDR, (void *)&ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFADDR): %s", strerror(errno));
		exit(1);
    }

    saddr = (struct sockaddr_in *)&ifr.ifr_netmask;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = htonl(netmask);
    if(ioctl(inet4, SIOCSIFNETMASK, (void *)&ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFNETMASK): %s", strerror(errno));
		exit(1);
    }

    // Activate interface.
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if(ioctl(inet4, SIOCSIFFLAGS, (void *)&ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFFLAGS): %s", strerror(errno));
		exit(1);
	}

    // Set MTU if it is specified.
	ifr.ifr_mtu = mtu;
	if(ioctl(inet4, SIOCSIFMTU, (void *)&ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFMTU): %s", strerror(errno));
		exit(1);
	}

    close(inet4);

    for (int i = 0; i < tun->queues; i++) {
        struct tundev_context *ctx = &tun->contexts[i];
        ctx->network_buffer = malloc(mtu + PRIMITIVE_BYTES);
    }
}
#else
static void
tun_close(uv_async_t *handle) {
    struct tundev_context *ctx =
                container_of(handle, struct tundev_context, async_handle);
    struct tundev *tun = ctx->tun;

    uv_poll_stop(&ctx->watcher);
    uv_close((uv_handle_t*) &ctx->async_handle, NULL);
    uv_close((uv_handle_t *)&ctx->inet, NULL);

    if (!tun->is_global_proxy) {
        clear_dns_query();
    }

    free(ctx->network_buffer);
    free(tun);

    logger_log(LOG_WARNING, "xTun stoped.");
}

int
tun_config(struct tundev *tun, int fd, int mtu, int global, int v,
           const char *server, const char *dns) {
    int rc;
    struct sockaddr addr;
    struct tundev_context *ctx;

    rc = resolve_addr(server, &addr);
    if (rc) {
        logger_stderr("Invalid server address");
        return 1;
    }

    struct sockaddr_in _dns_server;
    uv_ip4_addr(dns, 53, &_dns_server);
    tun->dns_server = *((struct sockaddr *) &_dns_server);

    verbose = v;

    tun->mtu = mtu;
    tun->server_addr = addr;
    tun->is_global_proxy = global;

    ctx = tun->contexts;
    ctx->tunfd = fd;
    ctx->network_buffer = malloc(mtu + PRIMITIVE_BYTES);

    uv_async_init(uv_default_loop(), &ctx->async_handle, tun_close);
    uv_unref((uv_handle_t *) &ctx->async_handle);

    return 0;
}
#endif

#ifndef ANDROID
void
tun_stop(struct tundev *tun) {
    if (tun->mode == TUN_MODE_SERVER) {
        uv_rwlock_destroy(&rwlock);
        clear_addrs(tun->raddrs);
    }

    if (tun->queues > 1) {
        for (int i = 0; i < tun->queues; i++) {
            struct tundev_context *ctx = &tun->contexts[i];
            uv_async_send(&ctx->async_handle);
        }

    } else {
        struct tundev_context *ctx = tun->contexts;
        uv_close((uv_handle_t *)&ctx->inet, NULL);
        uv_poll_stop(&ctx->watcher);
        // valgrind may generate a false alarm here
        if(ioctl(ctx->tunfd, TUNSETPERSIST, 0) < 0) {
            logger_stderr("ioctl(TUNSETPERSIST): %s", strerror(errno));
        }
        close(ctx->tunfd);
    }

}
#else
void
tun_stop(struct tundev *tun) {
    struct tundev_context *ctx = tun->contexts;
    uv_async_send(&ctx->async_handle);
}
#endif

static void
queue_close(uv_async_t *handle) {
    struct tundev_context *ctx =
            container_of(handle, struct tundev_context, async_handle);
    uv_close((uv_handle_t *)&ctx->inet, NULL);
    uv_close((uv_handle_t *)&ctx->async_handle, NULL);
    uv_poll_stop(&ctx->watcher);
    // valgrind may generate a false alarm here
    if(ioctl(ctx->tunfd, TUNSETPERSIST, 0) < 0) {
        logger_stderr("ioctl(TUNSETPERSIST): %s", strerror(errno));
        close(ctx->tunfd);
    }
}

static void
queue_start(void *arg) {
    int rc;
    uv_loop_t loop;
    struct tundev *tun;
    struct tundev_context *ctx;

    ctx = arg;
    tun = ctx->tun;

    uv_loop_init(&loop);
    uv_async_init(&loop, &ctx->async_handle, queue_close);
    uv_udp_init(&loop, &ctx->inet);

    if ((rc = uv_udp_open(&ctx->inet, ctx->inet_fd))) {
        logger_stderr("UDP open error: %s", uv_strerror(rc));
        exit(1);
    }

    if (tun->mode == TUN_MODE_SERVER) {
        rc = uv_udp_bind(&ctx->inet, &tun->bind_addr, UV_UDP_REUSEADDR);
        if (rc) {
            logger_stderr("Bind error: %s", uv_strerror(rc));
            exit(1);
        }
    }

    uv_udp_recv_start(&ctx->inet, inet_alloc_cb, inet_recv_cb);

    uv_poll_init(&loop, &ctx->watcher, ctx->tunfd);
    uv_poll_start(&ctx->watcher, UV_READABLE, poll_cb);

    uv_run(&loop, UV_RUN_DEFAULT);

    loop_close(&loop);
    uv_sem_post(&ctx->semaphore);
}

static void
walk_close_cb(uv_handle_t *handle, void *arg) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}

static void
loop_close(uv_loop_t *loop) {
    uv_walk(loop, walk_close_cb, NULL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
}

static void
signal_close() {
    for (int i = 0; i <= 2; i++) {
        uv_signal_stop(&signals[i].sig);
    }
}

static void
signal_cb(uv_signal_t *handle, int signum) {
    if (signum == SIGINT || signum == SIGQUIT) {
        char *name = signum == SIGINT ? "SIGINT" : "SIGQUIT";
        logger_log(LOG_INFO, "Received %s, scheduling shutdown...", name);

        signal_close();

        struct tundev *tun = handle->data;
        tun_stop(tun);
    }
}

static void
signal_install(uv_loop_t *loop, uv_signal_cb cb, void *data) {
    signals[0].signum = SIGINT;
    signals[1].signum = SIGQUIT;
    for (int i = 0; i <= 2; i++) {
        signals[i].sig.data = data;
        uv_signal_init(loop, &signals[i].sig);
        uv_signal_start(&signals[i].sig, cb, signals[i].signum);
    }
}

int
tun_start(struct tundev *tun) {
    int i, err;
    uv_loop_t *loop = uv_default_loop();

    if (tun->mode == TUN_MODE_SERVER) {
        uv_rwlock_init(&rwlock);
        for (i = 0; i < HASHSIZE; i++) {
            tun->raddrs[i] = NULL;
        }
    }

    if (tun->queues > 1) {
        for (i = 0; i < tun->queues; i++) {
            uv_thread_t thread_id;
            struct tundev_context *ctx = &tun->contexts[i];
            err = uv_sem_init(&ctx->semaphore, 0);
            err = uv_thread_create(&thread_id, queue_start, ctx);
        }

        signal_install(loop, signal_cb, tun);

        uv_run(loop, UV_RUN_DEFAULT);
        loop_close(loop);

        for (i = 0; i < tun->queues; i++) {
            uv_sem_wait(&tun->contexts[i].semaphore);
        }

    } else {
        struct tundev_context *ctx = tun->contexts;

        uv_udp_init(loop, &ctx->inet);

        if (tun->mode == TUN_MODE_SERVER) {
            err = uv_udp_bind(&ctx->inet, &tun->bind_addr, UV_UDP_REUSEADDR);
            if (err) {
                logger_stderr("bind error: %s", uv_strerror(err));
                return 1;
            }
        }

        uv_udp_recv_start(&ctx->inet, inet_alloc_cb, inet_recv_cb);

#ifdef ANDROID
        uv_os_fd_t fd = 0;
        err = uv_fileno((uv_handle_t*) &ctx->inet, &fd);
        if (err) {
            logger_log(LOG_ERR, "Get fileno error: %s", uv_strerror(err));
            return 1;
        }
        protectSocket(fd);
        logger_log(LOG_INFO, "xTun started.");
#endif

        uv_poll_init(loop, &ctx->watcher, ctx->tunfd);
        uv_poll_start(&ctx->watcher, UV_READABLE, poll_cb);

#ifndef ANDROID
        signal_install(loop, signal_cb, tun);
#endif

        uv_run(loop, UV_RUN_DEFAULT);

        loop_close(loop);
    }

    return 0;
}
