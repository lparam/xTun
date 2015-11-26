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
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/route.h>
#include <netinet/ip.h>

#include "uv.h"
#include "logger.h"


#if defined(_WIN32)
#define strdup _strdup
#endif

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

int
resolve_addr(const char *buf, struct sockaddr *addr) {
    char *p;
    char *tmp = strdup(buf);
    int rc = 0;
    long port;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    if ((p = strrchr(tmp, ':')) == NULL) {
        logger_log(LOG_ERR, "Address must contain port number: %s", tmp);
        rc = 1;
        goto err;
    }
    *p++ = '\0';

    port = strtol(p, NULL, 10);
    if ((port <= 0) || (port >= 65536)) {
        logger_log(LOG_ERR, "Invalid port number: %s", p);
        rc = 1;
        goto err;
    }

    /* If the IP address contains ':', it's IPv6; otherwise, IPv4 or domain. */
    if (strchr(tmp, ':') == NULL) {
        rc = uv_ip4_addr(tmp, port, &addr4);
        if (rc) {
            struct addrinfo hints;
            struct addrinfo *result, *rp;

            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            rc = 0;

            int err = getaddrinfo(tmp, p, &hints, &result);
            if (err != 0) {
                logger_stderr("Resolve %s error: %s", tmp, gai_strerror(err));
                rc = 1;
                goto err;
            }

            // IPV4 priority
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
                logger_stderr("Failed to resolve address: %s", tmp);
                rc = 1;
            }

            freeaddrinfo(result);
            goto err;

        } else {
            *addr = *(struct sockaddr*)&addr4;
        }

    } else {
        uv_ip6_addr(tmp, port, &addr6);
        *addr = *(struct sockaddr*)&addr6;
    }

err:
    free(tmp);
    return rc;
}

int
ip_name(const struct sockaddr *ip, char *name, size_t size) {
    int port = -1;
    if (ip->sa_family == AF_INET) {
        uv_ip4_name((const struct sockaddr_in*)ip, name, size);
        port = ntohs(((const struct sockaddr_in*)ip)->sin_port);
    } else if (ip->sa_family == AF_INET6) {
        uv_ip6_name((const struct sockaddr_in6*)ip, name, size);
        port = ntohs(((const struct sockaddr_in6*)ip)->sin6_port);
    }
    return port;
}

static inline in_addr_t *
as_in_addr(struct sockaddr *sa) {
    return &((struct sockaddr_in *)sa)->sin_addr.s_addr;
}

int
add_route(const char *name, const char *address, int prefix) {
    int rc = 0;
    int inet4 = socket(AF_INET, SOCK_DGRAM, 0);

    struct rtentry rt4;
    memset(&rt4, 0, sizeof(rt4));
    rt4.rt_dev = (char *)name;
    rt4.rt_flags = RTF_UP;
    rt4.rt_dst.sa_family = AF_INET;
    rt4.rt_genmask.sa_family = AF_INET;

    if (inet_pton(AF_INET, address, as_in_addr(&rt4.rt_dst)) != 1 ||
            prefix < 0 || prefix > 32) {
        rc = 1;
    }

    in_addr_t mask = prefix ? (~0 << (32 - prefix)) : 0x80000000;
    *as_in_addr(&rt4.rt_genmask) = htonl(mask);
    if (ioctl(inet4, SIOCADDRT, &rt4) && errno != EEXIST) {
        rc = 1;
    }

    if (!prefix) {
        // Split the route instead of replacing the default route.
        *as_in_addr(&rt4.rt_dst) ^= htonl(0x80000000);
        if (ioctl(inet4, SIOCADDRT, &rt4) && errno != EEXIST) {
            rc = 1;
        }
    }

    close(inet4);
    return rc;
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
#ifdef SO_REUSEPORT
        int yes = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))) {
            logger_stderr("setsockopt SO_REUSEPORT error: %s", strerror(errno));
        }
#endif
    }
    return sock;
}
