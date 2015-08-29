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

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "tun.h"


struct tundev {
    char iface[128];
    char ifconf[128];
    uint8_t hwaddr[6];
	int tunfd;
    int mode;
    int mtu;
    struct sockaddr bind_addr;
    struct sockaddr server_addr;
    uv_udp_t inet;
    uv_poll_t watcher;
};

struct raddr {
    struct in_addr tun_addr;
	struct sockaddr addr;
	struct raddr *next;
};

#define HASHSIZE 256
static struct raddr *raddrs[HASHSIZE];


static uint32_t
hash_addr(uint32_t addr) {
	uint32_t a = addr >> 24;
	uint32_t b = addr >> 12;
	uint32_t c = addr;
	return (a + b + c) % HASHSIZE;
}

static struct raddr *
find_addr(uint32_t addr) {
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
save_addr(uint32_t tun_addr, const struct sockaddr *addr) {
	int h = hash_addr(tun_addr);
	struct raddr *ra = malloc(sizeof(struct raddr));
	memset(ra, 0, sizeof(*ra));
    ra->tun_addr.s_addr = tun_addr;
    ra->addr = *addr;
	ra->next = raddrs[h];
	raddrs[h] = ra;
}

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

static void
inet_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct tundev *tun = (struct tundev *) handle->data;
    buf->base = malloc(tun->mtu + PRIMITIVE_BYTES);
    buf->len = tun->mtu + PRIMITIVE_BYTES;
}

static void
inet_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        uint8_t *m = (uint8_t *)buf->base;
        ssize_t mlen = nread;
        int rc = crypto_decrypt(m, (uint8_t *)buf->base, mlen);
        if (rc) {
            logger_log(LOG_ERR, "Invalid udp packet");
            goto err;
        }

        if (verbose) {
            char saddr[24] = {0}, daddr[24] = {0};
            struct iphdr *iphdr = (struct iphdr *) m;
            char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            strcpy(saddr, a);
            a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
            strcpy(daddr, a);
            logger_log(LOG_INFO, "Received %ld bytes from %s to %s", mlen, saddr, daddr);
        }

        struct tundev *tun = handle->data;

        if (tun->mode == TUN_MODE_SERVER) {
            // TODO: Compare source address
            struct iphdr *iphdr = (struct iphdr *) m;
            struct raddr *ra = find_addr(iphdr->saddr);
            if (ra == NULL) {
                char saddr[24] = {0}, daddr[24] = {0};
                char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
                strcpy(saddr, a);
                a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
                strcpy(daddr, a);
                logger_log(LOG_WARNING, "Cache miss: %s -> %s", saddr, daddr);
                save_addr(iphdr->saddr, addr);

            } else {
                if (memcmp(&ra->addr, addr, sizeof(*addr))) {
                    ra->addr = *addr;
                }
            }
        }

        for (;;) {
            int rc = write(tun->tunfd, m, mlen - PRIMITIVE_BYTES);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                } else {
                    logger_log(LOG_ERR, "Write tun: %s", strerror(errno));
                    exit(1);
                }

            } else {
                break;
            }
        }
    }

err:
    free(buf->base);
}

static void
inet_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "Forward to server failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    free(buf->base);
    free(req);
}

static void
poll_cb(uv_poll_t *watcher, int status, int events) {
    if (events == UV_READABLE) {
        struct sockaddr *addr;
        struct tundev *tun = container_of(watcher, struct tundev, watcher);
        uint8_t *tunbuf = malloc(PRIMITIVE_BYTES + tun->mtu);
        uint8_t *m = tunbuf + PRIMITIVE_BYTES;
        int mlen = read(tun->tunfd, m, tun->mtu);

        if (mlen <= 0) {
            logger_log(LOG_ERR, "mlen: %d", mlen);
            free(tunbuf);
            return;
        }

        struct iphdr *iphdr = (struct iphdr *) m;

        if (tun->mode == TUN_MODE_SERVER) {
            struct raddr *ra = find_addr(iphdr->daddr);
            if (ra == NULL) {
                char saddr[24] = {0}, daddr[24] = {0};
                char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
                strcpy(saddr, a);
                a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
                strcpy(daddr, a);
                logger_stderr("Destination address miss: %s -> %s", saddr, daddr);
                return;
            }
            addr = &ra->addr;

        } else {
            addr = &tun->server_addr;
        }

        if (verbose) {
            char saddr[24] = {0}, daddr[24] = {0};
            char *addr = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
            strcpy(saddr, addr);
            addr = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
            strcpy(daddr, addr);
            logger_log(LOG_INFO, "Sending %ld bytes from %s to %s", mlen, saddr, daddr);
        }

        crypto_encrypt(tunbuf, m, mlen);

        uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
        uv_buf_t *outbuf = (uv_buf_t *)(write_req + 1);
        outbuf->base = (char *)tunbuf;
        outbuf->len = PRIMITIVE_BYTES + mlen;
        write_req->data = tun;
        uv_udp_send(write_req, &tun->inet, outbuf, 1, addr, inet_send_cb);
    }
}

struct tundev *
tun_alloc(char *iface) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        logger_stderr("Open /dev/net/tun: %s", strerror(errno));
        exit(1);
	}

	memset(&ifr, 0, sizeof ifr);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        logger_stderr("ioctl(TUNSETIFF): %s", strerror(errno));
		close(fd);
        exit(1);
	}

    struct tundev *tun = malloc(sizeof(*tun));
    memset(tun, 0, sizeof(*tun));
    tun->tunfd = fd;
    strcpy(tun->iface, iface);

	return tun;
}

void
tun_free(struct tundev *tun) {
    free(tun);
}

void
tun_config(struct tundev *tun, const char *ifconf, int mtu, int mode, struct sockaddr *addr) {
    strcpy(tun->ifconf, ifconf);
    tun->mtu = mtu;
    tun->mode = mode;
    if (mode == TUN_MODE_CLIENT) {
        tun->server_addr = *addr;
    } else {
        tun->bind_addr = *addr;
    }

	char *nmask = strchr(ifconf, '/');
	uint8_t ipaddr[16] = {0};
	memcpy(ipaddr, ifconf, (uint32_t) (nmask - ifconf));

	if(!nmask) {
		logger_stderr("ifconf syntax error: %s", ifconf);
		exit(0);
	}

	in_addr_t netmask = 0xffffffff;
	netmask = (netmask << (32 - atoi(++nmask)));

    int tmp_fd = socket( AF_INET, SOCK_DGRAM, 0);
	if (tmp_fd < 0) {
		logger_stderr("Can't create tun device (udp socket): %s", strerror(errno));
        exit(1);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, tun->iface, IFNAMSIZ);

	struct sockaddr_in *saddr= (struct sockaddr_in *) &ifr.ifr_addr;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = inet_addr((const char *) ipaddr);
	if(saddr->sin_addr.s_addr == INADDR_NONE) {
        logger_stderr("Invalid IP address: %s", ifconf);
		exit(1);
	}
    if(ioctl(tmp_fd, SIOCSIFADDR, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFADDR): %s", strerror(errno));
		exit(1);
    }

    saddr = (struct sockaddr_in *)&ifr.ifr_netmask;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = htonl(netmask);
    if(ioctl(tmp_fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFNETMASK): %s", strerror(errno));
		exit(1);
    }

	ifr.ifr_flags |= IFF_UP |IFF_RUNNING;
	if(ioctl(tmp_fd, SIOCSIFFLAGS, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFFLAGS): %s", strerror(errno));
		exit(1);
	}

	ifr.ifr_mtu = mtu;
	if(ioctl(tmp_fd, SIOCSIFMTU, (void *) &ifr) < 0) {
        logger_stderr("ioctl(SIOCSIFMTU): %s", strerror(errno));
		exit(1);
	}

    close(tmp_fd);
}

void
tun_stop(struct tundev *tun) {
    if (tun->mode == TUN_MODE_SERVER) {
        clear_addrs(raddrs);
    }
    uv_close((uv_handle_t *)&tun->inet, NULL);
    uv_poll_stop(&tun->watcher);
	if(ioctl(tun->tunfd, TUNSETPERSIST, 0) < 0) {
        logger_stderr("ioctl(TUNSETPERSIST): %s", strerror(errno));
		close(tun->tunfd);
	}
}

int
tun_start(uv_loop_t *loop, struct tundev *tun) {
    tun->inet.data = tun;
    tun->watcher.data = tun;

    uv_udp_init(loop, &tun->inet);
    if (tun->mode == TUN_MODE_SERVER) {
        for (int i = 0; i < HASHSIZE; i++) {
            raddrs[i] = NULL;
        }

        int rc = uv_udp_bind(&tun->inet, &tun->bind_addr, UV_UDP_REUSEADDR);
        if (rc) {
            logger_stderr("bind error: %s", uv_strerror(rc));
            return 1;
        }
    }
    uv_udp_recv_start(&tun->inet, inet_alloc_cb, inet_recv_cb);

    uv_poll_init(loop, &tun->watcher, tun->tunfd);
    uv_poll_start(&tun->watcher, UV_READABLE, poll_cb);

    return 0;
}
