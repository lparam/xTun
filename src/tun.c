#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
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

uv_rwlock_t clients_rwlock;
rwlock_t peers_rwlock;
peer_t *peers[HASHSIZE];

int debug;
int verbose;
int protocol;
int multicast;
uint32_t nf_mark;
uint8_t mode;

#ifdef ANDROID
int dns_global;
struct sockaddr dns_server;
#endif

typedef struct tundev_ctx {
    uv_poll_t        watcher;
    uv_sem_t         semaphore;
    uv_async_t       async_handle;

    udp_t           *udp;
    tcp_server_t    *tcp_server;
    tcp_client_t    *tcp_client;

    int              tunfd;
    struct tundev   *tun;
} tundev_ctx_t;

typedef struct tundev {
    char                   iface[IFNAMSIZ];
    char                   ifconf[128];
    int                    mtu;
    in_addr_t              addr;
    in_addr_t              network;
    in_addr_t              netmask;

    uint32_t               queues;
    struct tundev_ctx      contexts[0];
} tundev_t;

struct signal_ctx {
    int            signum;
    uv_signal_t    sig;
} signals[2];

static void loop_close(uv_loop_t *loop);
static void signal_cb(uv_signal_t *handle, int signum);
static void signal_install(uv_loop_t *loop, uv_signal_cb cb, void *data);

int
tun_write(tundev_ctx_t *ctx, uint8_t *buf, ssize_t len) {
    uint8_t *pos = buf;
    size_t remaining = len;
    while(remaining) {
        ssize_t sz = write(ctx->tunfd, pos, remaining);
        if(sz == -1) {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                logger_stderr("tun write (%d: %s)", errno, strerror(errno));
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

int tun_network_check(struct tundev_ctx *ctx, struct iphdr *iphdr) {
    in_addr_t client_network = iphdr->saddr & htonl(ctx->tun->netmask);
    if (client_network != ctx->tun->network) {
        return 1;
    }
    return 0;
}

static int
dispatch(buffer_t *tunbuf, tundev_ctx_t *ctx) {
    char saddr[24] = {0}, daddr[24] = {0};
    struct iphdr *iphdr = (struct iphdr *) tunbuf->data;

    if (iphdr->version != 4) {
        logger_log(LOG_WARNING, "Discard non-IPv4 packet");
        return 1;
    }

    if (IN_MULTICAST(ntohl(iphdr->daddr)) && !multicast) {
        parse_addr(iphdr, saddr, daddr);
        logger_log(LOG_DEBUG, "Discard Multicast %s -> %s", saddr, daddr);
        return 1;
    }

    if (mode == xTUN_SERVER) {
        rwlock_rlock(&peers_rwlock);
        peer_t *peer = peer_lookup(iphdr->daddr, peers);
        rwlock_runlock(&peers_rwlock);
        if (peer) {
            // TODO: use peerops_t
            assert(peer->protocol == xTUN_TCP || peer->protocol == xTUN_UDP);
            if (peer->protocol == xTUN_TCP) {
                tcp_server_send(peer, tunbuf);
            } else {
                udp_send(ctx->udp, tunbuf, &peer->remote_addr);
            }

        } else {
            in_addr_t network = iphdr->daddr & htonl(ctx->tun->netmask);
            if (network == ctx->tun->network) {
                parse_addr(iphdr, saddr, daddr);
                logger_log(LOG_WARNING, "Peer is not connected: %s -> %s", saddr, daddr);
            }
            return 1;
        }

    } else {
        in_addr_t network = iphdr->saddr & htonl(ctx->tun->netmask);
        if (network != ctx->tun->network) {
            parse_addr(iphdr, saddr, daddr);
            logger_log(LOG_WARNING, "Discard %s -> %s", saddr, daddr);
            return 1;
        }

#ifdef ANDROID_RESERVED
        if (verbose) {
            logger_log(LOG_DEBUG, "%s -> %s", saddr, daddr);
        }
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

    if (dispatch(&tunbuf, ctx)) {
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
tun_alloc(const char *iface, uint32_t parallel) {
    int i, err, fd, nqueues;
    tundev_t *tun;

    nqueues = 1;
#ifdef IFF_MULTI_QUEUE
    nqueues = mode == xTUN_SERVER ? parallel : 1;
#endif

    size_t ctxsz = sizeof(tundev_ctx_t) * nqueues;
    tun = malloc(sizeof(*tun) + ctxsz);
    memset(tun, 0, sizeof(*tun) + ctxsz);
    tun->queues = nqueues;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#ifdef IFF_MULTI_QUEUE
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
#endif
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface == NULL ? "" : iface);

    for (i = 0; i < nqueues; i++) {
        if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 ) {
            logger_stderr("Open /dev/net/tun (%s)", strerror(errno));
            goto err;
        }
        err = ioctl(fd, TUNSETIFF, (void *)&ifr);
        if (err) {
            err = errno;
            (void) close(fd);
            errno = err;
            logger_stderr("Config tun (%s)", strerror(errno));
            goto err;
        }
        tundev_ctx_t *ctx = &tun->contexts[i];
        ctx->tun = tun;
        ctx->tunfd = fd;
    }

    snprintf(tun->iface, IFNAMSIZ, "%s", ifr.ifr_name);

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
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tun->iface);

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
    logger_log(LOG_INFO, "Global DNS: %s", global ? "true" : "false");

    ctx->tunfd = fd;

    uv_async_init(uv_default_loop(), &ctx->async_handle, tun_close);
    uv_unref((uv_handle_t *) &ctx->async_handle);

    return 0;
}
#endif

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
tun_run(tundev_t *tun, peer_addr_t addr) {
#else
tun_run(tundev_t *tun, const char *server, int port) {
    peer_addr_t addr;
    strncpy(addr.node, server, sizeof(addr.node)-1);
    addr.port = port;
    if (protocol == xTUN_UDP && resolve_addr(server, port, &addr.addr)) {
        logger_stderr("Invalid server address");
        return 1;
    }
#endif
    uv_loop_t *loop = uv_default_loop();

    if (mode == xTUN_SERVER) {
        rwlock_init(&peers_rwlock);
        uv_rwlock_init(&clients_rwlock);
        peer_init(peers);
    }

    if (mode == xTUN_SERVER && tun->queues > 1) {
        int i;
        for (i = 0; i < tun->queues; i++) {
            uv_thread_t thread_id;
            tundev_ctx_t *ctx = &tun->contexts[i];
            ctx->udp = udp_new(ctx, &addr.addr, ctx->tun->mtu);
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
            ctx->udp = udp_new(ctx, &addr.addr, ctx->tun->mtu);
            ctx->tcp_server = tcp_server_new(ctx, &addr.addr, ctx->tun->mtu);
            udp_start(ctx->udp, loop);
            tcp_server_start(ctx->tcp_server, loop);

        } else {
            if (protocol == xTUN_TCP) {
                ctx->tcp_client = tcp_client_new(ctx, &addr, ctx->tun->mtu);
                tcp_client_start(ctx->tcp_client, loop);
            } else {
                ctx->udp = udp_new(ctx, &addr.addr, ctx->tun->mtu);
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
        uv_rwlock_destroy(&clients_rwlock);
        peer_destroy(peers);
    }

    return 0;
}
