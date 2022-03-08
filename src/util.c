#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/route.h>
#include <netinet/ip.h>

#include "uv.h"
#include "logger.h"
#include "util.h"


#define MAX_LINE_LENGTH_BYTES (64)
#define DEFAULT_LINE_LENGTH_BYTES (16)


static int
print_buffer(const void *data, uint32_t count, uint32_t width, uint32_t linelen) {
    /* linebuf as a union causes proper alignment */
    union linebuf {
        uint32_t ui[MAX_LINE_LENGTH_BYTES/sizeof(uint32_t) + 1];
        uint16_t us[MAX_LINE_LENGTH_BYTES/sizeof(uint16_t) + 1];
        uint8_t  uc[MAX_LINE_LENGTH_BYTES/sizeof(uint8_t) + 1];
    } lb;

    uint32_t i;
    intptr_t addr = (intptr_t)data;

    if (linelen * width > MAX_LINE_LENGTH_BYTES)
        linelen = MAX_LINE_LENGTH_BYTES / width;
    if (linelen < 1)
        linelen = DEFAULT_LINE_LENGTH_BYTES / width;

    while (count) {
        uint32_t thislinelen = linelen;

        printf("%p:", data);

        /* check for overflow condition */
        if (count < thislinelen)
            thislinelen = count;

        /* Copy from memory into linebuf and print hex values */
        for (i = 0; i < thislinelen; i++) {
            uint32_t x;
            if (width == 4)
                x = lb.ui[i] = *(volatile uint32_t *)data;
            else if (width == 2)
                x = lb.us[i] = *(volatile uint16_t *)data;
            else
                x = lb.uc[i] = *(volatile uint8_t *)data;
            printf(i % (linelen / 2) ? " %0*x" : "  %0*x", width * 2, x);
#if defined(_MSC_VER)
			(uint8_t *)data += width;
#else
			data += width;
#endif
        }

        while (thislinelen < linelen) {
            /* fill line with whitespace for nice ASCII print */
            for (i = 0; i < width * 2 + 1; i++) {
                printf(" ");
            }
            linelen--;
        }

        /* Print data in ASCII characters */
        for (i = 0; i < thislinelen * width; i++) {
            if (!isprint(lb.uc[i]) || lb.uc[i] >= 0x80)
                lb.uc[i] = '.';
        }
        lb.uc[i] = '\0';
        printf("    %s\n", lb.uc);

        /* update references */
        addr += thislinelen * width;
        count -= thislinelen;
    }

    return 0;
}

void
dump_hex(const void *data, uint32_t len, char *title) {
    printf("\t  [%s] %d octets\n", title, len);
    print_buffer(data, len, 1, 16);
}


void
print_rss() {
    size_t rss;
    uv_resident_set_memory(&rss);
    logger_log(LOG_DEBUG, "resident set memory: %llu", (unsigned long long) rss);
}

int
resolve_addr(const char *buf, int port, struct sockaddr *addr) {
    int rc = 0;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    if ((port <= 0) || (port >= 65536)) {
        logger_log(LOG_ERR, "Invalid port number: %d", port);
        rc = 1;
        goto err;
    }

    /* If the IP address contains ':', it's IPv6; otherwise, IPv4 or domain. */
    if (strchr(buf, ':') == NULL) {
        rc = uv_ip4_addr(buf, port, &addr4);
        if (rc) {
            struct addrinfo hints;
            struct addrinfo *result, *rp;

            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            rc = 0;

            char service[6] = {0};
            snprintf(service, 6, "%d", port);
            int err = getaddrinfo(buf, service, &hints, &result);
            if (err != 0) {
                logger_stderr("Resolve %s error: %s", buf, gai_strerror(err));
                rc = 1;
                goto err;
            }

            /* IPV4 priority */
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    memcpy(addr, rp->ai_addr, sizeof(struct sockaddr_in));
                    break;
                }
            }

            if (rp == NULL) {
                for (rp = result; rp != NULL; rp = rp->ai_next) {
                    if (rp->ai_family == AF_INET6) {
                        memcpy(addr, rp->ai_addr, sizeof(struct sockaddr_in6));
                        break;
                    }
                }
            }

            if (rp == NULL) {
                logger_stderr("resolve address failed: %s", buf);
                rc = 1;
            }

            freeaddrinfo(result);
            goto err;

        } else {
            *addr = *((struct sockaddr *) &addr4);
        }

    } else {
        uv_ip6_addr(buf, port, &addr6);
        *addr = *((struct sockaddr *) &addr6);
    }

err:
    return rc;
}

int
ip_name(const struct sockaddr *ip, char *name, size_t size) {
    int port = -1;
    if (ip->sa_family == AF_INET) {
        uv_ip4_name((const struct sockaddr_in *) ip, name, size);
        port = ntohs(((const struct sockaddr_in *) ip)->sin_port);
    } else if (ip->sa_family == AF_INET6) {
        uv_ip6_name((const struct sockaddr_in6 *) ip, name, size);
        port = ntohs(((const struct sockaddr_in6 *) ip)->sin6_port);
    }
    return port;
}

int
create_socket(int type, int reuse) {
    int sock;
    sock = socket(AF_INET, type, IPPROTO_IP);
    if (sock < 0) {
        logger_stderr("socket error: %s", strerror(errno));
        return -1;
    }
    if (reuse) {
        int on = 1;
#ifdef SO_REUSEPORT
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))) {
            logger_stderr("setsockopt SO_REUSEPORT error: %s", strerror(errno));
        }
#else
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
            logger_stderr("setsockopt SO_REUSEADDR error: %s", strerror(errno));
        }
#endif
    }
    return sock;
}

int tcp_opts(int fd, uint32_t mark) {
    int on = 1;

    (void) setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
#ifdef TCP_QUICKACK
    (void) setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &on, sizeof on);
#else
    (void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
#endif
#ifdef TCP_CONGESTION
    (void) setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, OUTER_CONGESTION_CONTROL_ALG,
                      sizeof OUTER_CONGESTION_CONTROL_ALG - 1);
#endif
#if BUFFERBLOAT_CONTROL && defined(TCP_NOTSENT_LOWAT)
    (void) setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT,
                      (uint32_t[]){ NOTSENT_LOWAT }, sizeof(uint32_t));
#endif
#ifdef TCP_USER_TIMEOUT
    (void) setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, (uint32_t[]){ TCP_TIMEOUT },
                      sizeof(uint32_t));
#endif

    socket_mark(fd, mark);

    return 0;
}

int socket_mark(int fd, uint32_t mark) {
#ifdef SO_MARK
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
        logger_stderr("setsockopt SO_MARK (%s)", strerror(errno));
        return 1;
    }
#endif
    return 0;
}

#ifndef ANDROID
pid_t gettid() {
    return syscall(SYS_gettid);
}
#endif

int
read_size(uint8_t *buffer) {
	int r = (int)buffer[0] << 8 | (int)buffer[1];
	return r;
}

void
write_size(uint8_t *buffer, int len) {
	buffer[0] = (len >> 8) & 0xff;
	buffer[1] = len & 0xff;
}

void
parse_addr(struct iphdr *iphdr, char *saddr, char *daddr) {
    char *a = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
    strcpy(saddr, a);
    a = inet_ntoa(*(struct in_addr *) &iphdr->daddr);
    strcpy(daddr, a);
}

static void *
uv_malloc(size_t size) {
    logger_log(LOG_DEBUG, "malloc %ld", size);
    return malloc(size);
}

static void *
uv_realloc(void *ptr, size_t size) {
    logger_log(LOG_DEBUG, "realloc %p %ld", ptr, size);
    return realloc(ptr, size);
}

static void *
uv_callc(size_t count, size_t size) {
    logger_log(LOG_DEBUG, "calloc %ld", size);
    return calloc(count, size);
}

static void
uv_free(void *ptr) {
    logger_log(LOG_DEBUG, "free %p", ptr);
    free(ptr);
}

int replace_allocator() {
    return uv_replace_allocator(uv_malloc, uv_realloc, uv_callc, uv_free);
}
