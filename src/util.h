#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <netinet/ip.h>


#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define ATOMIC_INC(ptr) __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST)


void dump_hex(const void *data, uint32_t len, char *title);
int resolve_addr(const char *buf, int port, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
int add_route(const char *name, const char *address, int prefix);
int create_socket(int type, int reuse);
pid_t gettid();
int read_size(uint8_t *buffer);
void write_size(uint8_t *buffer, int len);
void parse_addr(struct iphdr *iphdr, char *saddr, char *daddr);
void print_rss();
int replace_allocator();

#endif // for #ifndef UTIL_H
