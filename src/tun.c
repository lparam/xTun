#include <unistd.h>
#include <string.h>
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
#include "tcp.h"
#include "udp.h"
#ifdef ANDROID
#include "android.h"
#endif


#define DNS_PORT 53

struct signal_ctx {
    int            signum;
    uv_signal_t    sig;
} signals[2];

static void loop_close(uv_loop_t *loop);
static void signal_cb(uv_signal_t *handle, int signum);
static void signal_install(uv_loop_t *loop, uv_signal_cb cb, void *data);


int
tun_write(int tunfd, uint8_t *buf, ssize_t len) {
    uint8_t *pos = buf;
    size_t remaining = len;
    while(remaining) {
        ssize_t sz = write(tunfd, pos, remaining);
        if(sz == -1) {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                logger_stderr("tun write error (%d: %s)", errno, strerror(errno));
                return -1;
            } else {
                continue;
            }
        }
        pos += sz;
        remaining -= sz;
    }
    return 0;
}

static int
route(buffer_t *tunbuf, tundev_ctx_t *ctx) {
    struct iphdr *iphdr = (struct iphdr *) tunbuf->data;
    if (iphdr->version != 4) {
        logger_log(LOG_NOTICE, "Discard non-IPv4 packet");
        return 1;
    }

    char saddr[24] = {0}, daddr[24] = {0};
    parse_addr(iphdr, saddr, daddr);
    in_addr_t network = iphdr->daddr & htonl(ctx->tun->netmask);
    if (network != ctx->tun->network) {
        logger_log(LOG_NOTICE, "Discard %s -> %s", saddr, daddr);
        return 1;
    }

    if (mode == xTUN_SERVER) {
        uv_rwlock_rdlock(&rwlock);
        peer_t *peer = peer_lookup(iphdr->daddr, peers);
        uv_rwlock_rdunlock(&rwlock);
        if (peer) {
            // TODO: use peerops_t
            assert(peer->protocol == xTUN_TCP || peer->protocol == xTUN_UDP);
            if (peer->protocol == xTUN_TCP) {
                tcp_server_send(peer, tunbuf);
            } else {
                udp_send(ctx->udp, tunbuf, &peer->remote_addr);
            }

        } else {
            logger_log(LOG_WARNING, "Peer is not connected: %s -> %s", saddr, daddr);
            return 1;
        }

    } else {
#ifdef ANDROID
        // TODO: Check full DNS packet
        if (!dns_global) {
            uint16_t frag = iphdr->frag_off & htons(0x1fff);
            if ((iphdr->protocol == IPPROTO_UDP) && (frag == 0)) {
                struct udphdr *udph = (struct udphdr *)
                                      (tunbuf->data + sizeof(struct iphdr));
                if (ntohs(udph->dest) == DNS_PORT) {
                    int rc = handle_local_dns_query(ctx->tunfd, &dns_server, tunbuf);
                    if (rc) {
                        return 0;
                    }
                }
            }
        }
#endif
        if (protocol == xTUN_TCP) {
            if (tcp_client_connected(ctx->tcp_client)) {
                tcp_client_send(ctx->tcp_client, tunbuf);

            } else {
                if (tcp_client_disconnected(ctx->tcp_client)) {
                    tcp_client_connect(ctx->tcp_client);
                }
                return 1;
            }

        } else {
            udp_send(ctx->udp, tunbuf, NULL);
        }
    }

    return 0;
}

static void
poll_cb(uv_poll_t *watcher, int status, int events) {
    tundev_ctx_t *ctx = container_of(watcher, tundev_ctx_t, watcher);

    buffer_t tunbuf;
    buffer_alloc(&tunbuf, ctx->tun->mtu + CRYPTO_MAX_OVERHEAD);

    int n = read(ctx->tunfd, tunbuf.data, ctx->tun->mtu);
    if (n <= 0) {
        logger_log(LOG_ERR, "tun read error (%d: %s)", errno, strerror(errno));
        return buffer_free(&tunbuf);
    }
    tunbuf.len = n;

    int rc = route(&tunbuf, ctx);
    if (rc) {
        buffer_free(&tunbuf);
    }
}

static void
close_tunfd(int fd) {
    /* valgrind may generate a false alarm here */
    if(ioctl(fd, TUNSETPERSIST, 0) < 0) {
        logger_stderr("ioctl(TUNSETPERSIST): %s", strerror(errno));
    }
    close(fd);
}

static void
close_network(tundev_ctx_t *ctx) {
    if (mode == xTUN_SERVER) {
        if (ctx->tcp_server) {
            tcp_server_stop(ctx->tcp_server);
        }
        udp_stop(ctx->udp);

    } else {
        if (protocol == xTUN_TCP) {
            tcp_client_stop(ctx->tcp_client);
        } else {
            udp_stop(ctx->udp);
        }
    }
}

#ifndef ANDROID
tundev_t *
tun_alloc(char *iface, uint32_t parallel) {
    int i, err, fd, nqueues;
    tundev_t *tun;

    nqueues = mode == xTUN_SERVER ? parallel : 1;

    size_t ctxsz = sizeof(tundev_ctx_t) * nqueues;
    tun = malloc(sizeof(*tun) + ctxsz);
    memset(tun, 0, sizeof(*tun) + ctxsz);
    tun->queues = nqueues;
    strcpy(tun->iface, iface);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, tun->iface, IFNAMSIZ);

    for (i = 0; i < nqueues; i++) {
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
        tundev_ctx_t *ctx = &tun->contexts[i];
        ctx->tun = tun;
        ctx->tunfd = fd;
    }

    return tun;
err:
    for (--i; i >= 0; i--) {
        tundev_ctx_t *ctx = &tun->contexts[i];
        close(ctx->tunfd);
    }
    free(tun);
    return NULL;
}
#else
tundev_t *
tun_alloc() {
    int queues = 1;
    size_t ctxsz = sizeof(tundev_ctx_t) * queues;

    tundev_t *tun = malloc(sizeof(*tun) + ctxsz);
    memset(tun, 0, sizeof(*tun) + ctxsz);
    tun->queues = queues;

    mode = xTUN_CLIENT;

    tundev_ctx_t *ctx = tun->contexts;
    ctx->tun = tun;

    return tun;
}
#endif

void
tun_free(tundev_t *tun) {
    for (int i = 0; i < tun->queues; i++) {
        tundev_ctx_t *ctx = &tun->contexts[i];
        if (mode == xTUN_SERVER) {
            if (ctx->tcp_server) {
                tcp_server_free(ctx->tcp_server);
            }
            udp_free(ctx->udp);

        } else {
            if (protocol == xTUN_TCP) {
                tcp_client_free(ctx->tcp_client);
            } else {
                udp_free(ctx->udp);
            }
        }
    }
    free(tun);
}

#ifndef ANDROID
void
tun_config(tundev_t *tun, const char *ifconf, int mtu) {
    tun->mtu = mtu;
    strcpy(tun->ifconf, ifconf);

	char *cidr = strchr(ifconf, '/');
	if(!cidr) {
		logger_stderr("ifconf syntax error: %s", ifconf);
		exit(0);
	}

	uint8_t ipaddr[16] = {0};
	memcpy(ipaddr, ifconf, (uint32_t) (cidr - ifconf));

	in_addr_t netmask = 0xffffffff;
	netmask = netmask << (32 - atoi(++cidr));
    tun->addr = inet_addr((const char *) ipaddr);
    tun->netmask = netmask;
    tun->network = inet_addr((const char *) ipaddr) & htonl(netmask);

    int inet4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (inet4 < 0) {
		logger_stderr("Can't create tun device (udp socket): %s",
                      strerror(errno));
        exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, tun->iface, IFNAMSIZ);

    struct sockaddr_in *saddr = (struct sockaddr_in *) &ifr.ifr_addr;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = inet_addr((const char *) ipaddr);
	if(saddr->sin_addr.s_addr == INADDR_NONE) {
        logger_stderr("Invalid IP address: %s", ifconf);
		exit(1);
	}
    if(ioctl(inet4, SIOCSIFADDR, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFADDR): %s", strerror(errno));
		exit(1);
    }

    saddr = (struct sockaddr_in *)&ifr.ifr_netmask;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = htonl(netmask);
    if(ioctl(inet4, SIOCSIFNETMASK, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFNETMASK): %s", strerror(errno));
		exit(1);
    }

    /* Activate interface. */
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if(ioctl(inet4, SIOCSIFFLAGS, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFFLAGS): %s", strerror(errno));
		exit(1);
	}

    /* Set MTU if it is specified. */
	ifr.ifr_mtu = mtu;
	if(ioctl(inet4, SIOCSIFMTU, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFMTU): %s", strerror(errno));
		exit(1);
	}

    close(inet4);
}
#else
static void
tun_close(uv_async_t *handle) {
    tundev_ctx_t *ctx = container_of(handle, tundev_ctx_t,
                                              async_handle);
    tundev_t *tun = ctx->tun;

    uv_close((uv_handle_t *) &ctx->async_handle, NULL);
    close_network(ctx);
    uv_poll_stop(&ctx->watcher);
    close_tunfd(ctx->tunfd);

    if (!dns_global) {
        clear_dns_query();
    }

    tun_free(tun);
}

int
tun_config(tundev_t *tun, const char *ifconf, int fd, int mtu, int prot,
           int global, int v, const char *dns)
{
    tundev_ctx_t *ctx = tun->contexts;

	char *cidr = strchr(ifconf, '/');
	if(!cidr) {
		logger_stderr("ifconf syntax error: %s", ifconf);
		exit(0);
	}

	uint8_t ipaddr[16] = {0};
	memcpy(ipaddr, ifconf, (uint32_t) (cidr - ifconf));

	in_addr_t netmask = 0xffffffff;
	netmask = netmask << (32 - atoi(++cidr));
    tun->addr = inet_addr((const char *) ipaddr);
    tun->netmask = netmask;
    tun->network = inet_addr((const char *) ipaddr) & htonl(netmask);

    verbose = v;
    protocol = prot;

    struct sockaddr_in ds;
    uv_ip4_addr(dns, DNS_PORT, &ds);
    dns_server = *((struct sockaddr *) &ds);

    tun->mtu = mtu;
    dns_global = global;

    ctx->tunfd = fd;

    uv_async_init(uv_default_loop(), &ctx->async_handle, tun_close);
    uv_unref((uv_handle_t *) &ctx->async_handle);

    return 0;
}
#endif

int tun_keepalive(tundev_t *tun, int on, unsigned int interval) {
    if (on && interval) {
        tun->keepalive_interval = interval;
    } else {
        tun->keepalive_interval = 0;
    }
    return 0;
}

void
tun_stop(tundev_t *tun) {
#ifndef ANDROID
    if (mode == xTUN_SERVER && tun->queues > 1) {
        for (int i = 0; i < tun->queues; i++) {
            tundev_ctx_t *ctx = &tun->contexts[i];
            uv_async_send(&ctx->async_handle);
        }

    } else {
        tundev_ctx_t *ctx = tun->contexts;
        close_network(ctx);
        uv_poll_stop(&ctx->watcher);
        close_tunfd(ctx->tunfd);
    }
#else
    tundev_ctx_t *ctx = tun->contexts;
    uv_async_send(&ctx->async_handle);
#endif
}

static void
queue_close(uv_async_t *handle) {
    tundev_ctx_t *ctx = container_of(handle, tundev_ctx_t, async_handle);
    uv_close((uv_handle_t *) &ctx->async_handle, NULL);
    close_network(ctx);
    uv_poll_stop(&ctx->watcher);
    close_tunfd(ctx->tunfd);
}

static void
queue_start(void *arg) {
    tundev_ctx_t *ctx = arg;
    uv_loop_t loop;

    uv_loop_init(&loop);
    uv_async_init(&loop, &ctx->async_handle, queue_close);

    udp_start(ctx->udp, &loop);
    /* tcp_server_start(ctx, &loop); */

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
    for (int i = 0; i < 2; i++) {
        uv_signal_stop(&signals[i].sig);
    }
}

static void
signal_cb(uv_signal_t *handle, int signum) {
    if (signum == SIGINT || signum == SIGQUIT) {
        char *name = signum == SIGINT ? "SIGINT" : "SIGQUIT";
        logger_log(LOG_INFO, "Received %s, scheduling shutdown...", name);

        signal_close();

        tundev_t *tun = handle->data;
        tun_stop(tun);
    }
}

static void
signal_install(uv_loop_t *loop, uv_signal_cb cb, void *data) {
    signals[0].signum = SIGINT;
    signals[1].signum = SIGQUIT;
    for (int i = 0; i < 2; i++) {
        signals[i].sig.data = data;
        uv_signal_init(loop, &signals[i].sig);
        uv_signal_start(&signals[i].sig, cb, signals[i].signum);
    }
}

int
#ifndef ANDROID
tun_run(tundev_t *tun, struct sockaddr addr) {
#else
tun_run(tundev_t *tun, const char *server, int port) {
    struct sockaddr addr;
    if (resolve_addr(server, port, &addr)) {
        logger_stderr("Invalid server address");
        return 1;
    }
#endif
    uv_loop_t *loop = uv_default_loop();

    if (mode == xTUN_SERVER) {
        uv_rwlock_init(&rwlock);
        peer_init(peers);
    }

    if (mode == xTUN_SERVER && tun->queues > 1) {
        int i;
        for (i = 0; i < tun->queues; i++) {
            uv_thread_t thread_id;
            tundev_ctx_t *ctx = &tun->contexts[i];
            ctx->udp = udp_new(ctx, &addr);
            uv_sem_init(&ctx->semaphore, 0);
            uv_thread_create(&thread_id, queue_start, ctx);
        }

        signal_install(loop, signal_cb, tun);

        uv_run(loop, UV_RUN_DEFAULT);

        loop_close(loop);

        for (i = 0; i < tun->queues; i++) {
            uv_sem_wait(&tun->contexts[i].semaphore);
        }

    } else {
        tundev_ctx_t *ctx = tun->contexts;

        if (mode == xTUN_SERVER) {
            ctx->udp = udp_new(ctx, &addr);
            ctx->tcp_server = tcp_server_new(ctx, &addr);
            udp_start(ctx->udp, loop);
            tcp_server_start(ctx->tcp_server, loop);

        } else {
            if (protocol == xTUN_TCP) {
                ctx->tcp_client = tcp_client_new(ctx, &addr);
                tcp_client_start(ctx->tcp_client, loop);
            } else {
                ctx->udp = udp_new(ctx, &addr);
                udp_start(ctx->udp, loop);
            }
        }

        uv_poll_init(loop, &ctx->watcher, ctx->tunfd);
        uv_poll_start(&ctx->watcher, UV_READABLE, poll_cb);

#ifndef ANDROID
        signal_install(loop, signal_cb, tun);
#endif

        uv_run(loop, UV_RUN_DEFAULT);

        loop_close(loop);
    }

    if (mode == xTUN_SERVER) {
        uv_rwlock_destroy(&rwlock);
        peer_destroy(peers);
    }

    return 0;
}
