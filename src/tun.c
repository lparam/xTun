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
                logger_stderr("Write tun error (%d: %s)",
                               errno, strerror(errno));
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

static void
close_tunfd(int fd) {
    /* valgrind may generate a false alarm here */
    if(ioctl(fd, TUNSETPERSIST, 0) < 0) {
        logger_stderr("ioctl(TUNSETPERSIST): %s", strerror(errno));
    }
    close(fd);
}

static void
close_network(struct tundev_context *ctx) {
    if (mode == xTUN_SERVER) {
        tcp_server_stop(ctx->tcp_server);
        udp_stop(ctx->udp);

    } else {
        if (protocol == xTUN_TCP) {
            tcp_client_stop(ctx->tcp_client);
        } else {
            udp_stop(ctx->udp);
        }
    }
}

static void
poll_cb(uv_poll_t *watcher, int status, int events) {
    struct tundev *tun;
    struct tundev_context *ctx;
    buffer_t tunbuf;

    ctx = container_of(watcher, struct tundev_context, watcher);
    tun = ctx->tun;

    // TODO: Use output buffer
    buffer_alloc(&tunbuf, tun->mtu);
    // printf("%s - buffer: %p - %p\n", __func__, &tunbuf, tunbuf.data);

    int n = read(ctx->tunfd, tunbuf.data, tunbuf.capacity);
    if (n <= 0) {
        logger_log(LOG_ERR, "tun read error");
        return buffer_free(&tunbuf);
    }
    tunbuf.len = n;

    struct iphdr *iphdr = (struct iphdr *) tunbuf.data;
    if (iphdr->version != 4) {
        logger_log(LOG_WARNING, "Discard non-IPv4 packet");
        return buffer_free(&tunbuf);
    }

    if (mode == xTUN_SERVER) {
        uv_rwlock_rdlock(&rwlock);
        peer_t *peer = lookup_peer(iphdr->daddr, peers);
        uv_rwlock_rdunlock(&rwlock);
        if (peer) {
            assert(peer->protocol == xTUN_TCP || peer->protocol == xTUN_UDP);
            if (peer->protocol == xTUN_TCP) {
                tcp_server_send(peer, &tunbuf);
            } else {
                udp_send(ctx->udp, &tunbuf, &peer->remote_addr);
            }

        } else {
            char saddr[24] = {0}, daddr[24] = {0};
            parse_addr(iphdr, saddr, daddr);
            in_addr_t network = iphdr->daddr & htonl(ctx->tun->netmask);
            if (network != ctx->tun->network) {
                logger_log(LOG_NOTICE, "Discard %s -> %s", saddr, daddr);
            } else {
                logger_log(LOG_WARNING, "Client is not connected: %s -> %s",
                           saddr, daddr);
            }
            return buffer_free(&tunbuf);
        }

    } else {
        in_addr_t network = iphdr->saddr & htonl(ctx->tun->netmask);
        if (network != ctx->tun->network) {
            char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            logger_log(LOG_ERR, "Invalid client: %s", a);
            return buffer_free(&tunbuf);
        }

#ifdef ANDROID
        // TODO: Check full DNS packet
        if (!tun->global) {
            uint16_t frag = iphdr->frag_off & htons(0x1fff);
            if ((iphdr->protocol == IPPROTO_UDP) && (frag == 0)) {
                struct udphdr *udph = (struct udphdr *)
                                      (tunbuf.data + sizeof(struct iphdr));
                if (ntohs(udph->dest) == DNS_PORT) {
                    int rc = handle_local_dns_query(ctx->tunfd,
                                                    &tun->dns_server, &tunbuf);
                    if (rc) {
                        return;
                    }
                }
            }
        }
#endif
        if (protocol == xTUN_TCP) {
            if (tcp_client_connected(ctx->tcp_client)) {
                tcp_client_send(ctx->tcp_client, &tunbuf);

            } else {
                if (tcp_client_disconnected(ctx->tcp_client)) {
                    tcp_client_connect(ctx->tcp_client);
                }
                return buffer_free(&tunbuf);
            }

        } else {
            udp_send(ctx->udp, &tunbuf, NULL);
        }
    }
}

#ifndef ANDROID
struct tundev *
tun_alloc(char *iface, uint32_t parallel) {
    int i, err, fd, nqueues;
    struct tundev *tun;

    nqueues = mode == xTUN_SERVER ? parallel : 1;

    size_t ctxsz = sizeof(struct tundev_context) * nqueues;
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
        struct tundev_context *ctx = &tun->contexts[i];
        ctx->tun = tun;
        ctx->tunfd = fd;
    }

    return tun;
err:
    for (--i; i >= 0; i--) {
        struct tundev_context *ctx = &tun->contexts[i];
        close(ctx->tunfd);
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
    tun->queues = queues;

    mode = xTUN_CLIENT;

    struct tundev_context *ctx = tun->contexts;
    ctx->tun = tun;

    return tun;
}
#endif

void
tun_free(struct tundev *tun) {
    for (int i = 0; i < tun->queues; i++) {
        struct tundev_context *ctx = &tun->contexts[i];
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
tun_config(struct tundev *tun, const char *ifconf, int mtu) {
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
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              async_handle);
    struct tundev *tun = ctx->tun;

    uv_close((uv_handle_t *) &ctx->async_handle, NULL);
    close_network(ctx);
    uv_poll_stop(&ctx->watcher);
    close_tunfd(ctx->tunfd);

    if (!tun->global) {
        clear_dns_query();
    }

    tun_free(tun);
}

int
tun_config(struct tundev *tun, const char *ifconf, int fd, int mtu, int prot,
           int global, int v, const char *dns)
{
    struct tundev_context *ctx = tun->contexts;

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

    struct sockaddr_in dns_server;
    uv_ip4_addr(dns, DNS_PORT, &dns_server);
    tun->dns_server = *((struct sockaddr *) &dns_server);

    tun->mtu = mtu;
    tun->global = global;

    ctx->tunfd = fd;

    uv_async_init(uv_default_loop(), &ctx->async_handle, tun_close);
    uv_unref((uv_handle_t *) &ctx->async_handle);

    return 0;
}
#endif

int tun_keepalive(struct tundev *tun, int on, unsigned int interval) {
    if (on && interval) {
        tun->keepalive_interval = interval;
    } else {
        tun->keepalive_interval = 0;
    }
    return 0;
}

void
tun_stop(struct tundev *tun) {
#ifndef ANDROID
    if (mode == xTUN_SERVER && tun->queues > 1) {
        for (int i = 0; i < tun->queues; i++) {
            struct tundev_context *ctx = &tun->contexts[i];
            uv_async_send(&ctx->async_handle);
        }

    } else {
        struct tundev_context *ctx = tun->contexts;
        close_network(ctx);
        uv_poll_stop(&ctx->watcher);
        close_tunfd(ctx->tunfd);
    }
#else
    struct tundev_context *ctx = tun->contexts;
    uv_async_send(&ctx->async_handle);
#endif
}

static void
queue_close(uv_async_t *handle) {
    struct tundev_context *ctx = container_of(handle, struct tundev_context,
                                              async_handle);
    uv_close((uv_handle_t *) &ctx->async_handle, NULL);
    close_network(ctx);
    uv_poll_stop(&ctx->watcher);
    close_tunfd(ctx->tunfd);
}

static void
queue_start(void *arg) {
    struct tundev_context *ctx = arg;
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

        struct tundev *tun = handle->data;
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
tun_run(struct tundev *tun, struct sockaddr addr) {
#else
tun_run(struct tundev *tun, const char *server, int port) {
    struct sockaddr addr;
    if (resolve_addr(server, port, &addr)) {
        logger_stderr("Invalid server address");
        return 1;
    }
#endif
    uv_loop_t *loop = uv_default_loop();

    if (mode == xTUN_SERVER) {
        uv_rwlock_init(&rwlock);
        init_peers(peers);
    }

    if (mode == xTUN_SERVER && tun->queues > 1) {
        int i;
        for (i = 0; i < tun->queues; i++) {
            uv_thread_t thread_id;
            struct tundev_context *ctx = &tun->contexts[i];
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
        struct tundev_context *ctx = tun->contexts;

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
        destroy_peers(peers);
    }

    return 0;
}
