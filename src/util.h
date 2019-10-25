#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <netinet/ip.h>


#define OUTER_CONGESTION_CONTROL_ALG "bbr"
#define BUFFERBLOAT_CONTROL 1
#define NOTSENT_LOWAT (128 * 1024)
#define TCP_TIMEOUT (60 * 1000)
#define SOCKET_MARK 20909U

#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define ATOMIC_INC(ptr) __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST)


void dump_hex(const void *data, uint32_t len, char *title);
int resolve_addr(const char *buf, int port, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
int create_socket(int type, int reuse);
int tcp_opts(int fd);
int socket_mark(int fd);
pid_t gettid();
int read_size(uint8_t *buffer);
void write_size(uint8_t *buffer, int len);
void parse_addr(struct iphdr *iphdr, char *saddr, char *daddr);
void print_rss();
int replace_allocator();

#endif // for #ifndef UTIL_H
