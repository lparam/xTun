#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "uv.h"
#include "logger.h"
#include "util.h"
#include "checksum.h"
#include "dns.h"
#include "tun.h"
#include "android.h"


struct dns_query {
    int tunfd;
    struct iphdr iphdr;
    struct udphdr udphdr;
    uv_udp_t handle;
};

struct query_cache {
	struct dns_query *query;
	struct query_cache *next;
};

#define HASHSIZE 256
static struct query_cache *caches[HASHSIZE];

static void handle_local_dns_answer(struct dns_query *query, uint8_t *buf, size_t len);

static uint16_t
hash_query(uint16_t port) {
	uint32_t a = port >> 8;
	uint32_t b = port;
	return (a + b) % HASHSIZE;
}

static struct query_cache *
find_query(uint16_t port) {
	int h = hash_query(port);
	struct query_cache *cache = caches[h];
	if (cache == NULL)
		return NULL;
	if (cache->query->udphdr.source == port)
		return cache;
	struct query_cache *last = cache;
	while (last->next) {
		cache = last->next;
        if (cache->query->udphdr.source == port) {
			return cache;
		}
		last = cache;
	}
	return NULL;
}

static void
save_query(uint16_t port, struct dns_query *query) {
	int h = hash_query(port);
	struct query_cache *cache = malloc(sizeof(struct query_cache));
	memset(cache, 0, sizeof(*cache));
    cache->query = query;
	cache->next = caches[h];
	caches[h] = cache;
}

void
clear_dns_query() {
	for (int i = 0; i < HASHSIZE; i++) {
        struct query_cache *cache  = caches[i];
        while (cache) {
            void *tmp = cache;
            cache = cache->next;
            uv_close((uv_handle_t *)&cache->query->handle, NULL);
            free(cache->query);
            free(tmp);
        }
		caches[i] = NULL;
	}
}

static void
dns_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(1024);
    buf->len = 1024;
}

static void
dns_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "Forward to server failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    free(buf->base - sizeof(struct iphdr) - sizeof(struct udphdr) - PRIMITIVE_BYTES);
    free(req);
}

static void
dns_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        struct dns_query *query = container_of(handle, struct dns_query, handle);
        handle_local_dns_answer(query, (uint8_t*)buf->base, nread);
    }
}

int
handle_local_dns_query(int tunfd, struct sockaddr *dns_server, uint8_t *buf, int buflen) {
    struct iphdr *iphdr = (struct iphdr *)buf;
    struct udphdr *udphdr = (struct udphdr *)(buf + sizeof(struct iphdr));

    buf += sizeof(struct iphdr) + sizeof(struct udphdr);
    buflen -= sizeof(struct iphdr) + sizeof(struct udphdr);

    int rc = filter_query(buf, buflen);

    if (!rc) {
        return 0;
    }

    struct dns_query *query = NULL;
    struct query_cache *cache = find_query(udphdr->source);
    if (cache == NULL) {
        query = malloc(sizeof(struct dns_query));
        memset(query, 0, sizeof(struct dns_query));
        query->iphdr = *iphdr;
        query->udphdr = *udphdr;
        query->tunfd = tunfd;
        save_query(udphdr->source, query);

        uv_udp_init(uv_default_loop(), &query->handle);
        uv_udp_recv_start(&query->handle, dns_alloc_cb, dns_recv_cb);

        uv_os_fd_t fd = 0;
        int rc = uv_fileno((uv_handle_t*) &query->handle, &fd);
        if (rc) {
            logger_log(LOG_ERR, "Get fileno error: %s", uv_strerror(rc));
            free(query);
            return 0;
        } else {
            protectSocket(fd);
        }

        char saddr[24] = {0}, daddr[30] = {0};
        char *addr = inet_ntoa(*(struct in_addr *) &iphdr->saddr);
        strcpy(saddr, addr);
        uv_ip4_name((const struct sockaddr_in *) dns_server, daddr, sizeof(daddr));
        logger_log(LOG_WARNING, "DNS Cache miss: %s:%d -> %s", saddr, ntohs(udphdr->source), daddr);

    } else {
        query = cache->query;
        query->iphdr = *iphdr;
        query->udphdr = *udphdr;
    }

    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *outbuf = (uv_buf_t *)(write_req + 1);
    outbuf->base = (char *)buf;
    outbuf->len = buflen;
    uv_udp_send(write_req, &query->handle, outbuf, 1, dns_server, dns_send_cb);

    return 1;
}

static void
handle_local_dns_answer(struct dns_query *query, uint8_t *buf, size_t len) {
    int dnsbuf_len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
    uint8_t *dnsbuf = malloc(dnsbuf_len);
    memset(dnsbuf, 0, dnsbuf_len);

    struct iphdr iphdr;
    struct udphdr udphdr;
    memset(&iphdr, 0, sizeof(iphdr));
    memset(&udphdr, 0, sizeof(udphdr));

    iphdr.protocol = query->iphdr.protocol;
    iphdr.version = query->iphdr.version;
    iphdr.daddr = query->iphdr.saddr;
    iphdr.saddr = query->iphdr.daddr;

    iphdr.id = query->iphdr.id;
    iphdr.frag_off = query->iphdr.frag_off;
    iphdr.ihl = query->iphdr.ihl;
    iphdr.ttl = query->iphdr.ttl;
    iphdr.tos = query->iphdr.tos;

    iphdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len);
    iphdr.check = checksum((uint16_t*)&iphdr, sizeof(struct iphdr));

    udphdr.dest = query->udphdr.source;
    udphdr.source = query->udphdr.dest;
    udphdr.len = htons(sizeof(struct udphdr) + len);
    udphdr.check = udp_checksum(&iphdr, &udphdr, buf, len);;

    memcpy(dnsbuf, &iphdr, sizeof(iphdr));
    memcpy(dnsbuf + sizeof(iphdr), &udphdr, sizeof(udphdr));
    memcpy(dnsbuf + sizeof(iphdr) + sizeof(udphdr), buf, len);

    for (;;) {
        int rc = write(query->tunfd, dnsbuf, dnsbuf_len);
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
