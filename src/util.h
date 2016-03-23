#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>


#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))


void dump_hex(const void *data, uint32_t len, char *title);
int resolve_addr(const char *buf, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
int add_route(const char *name, const char *address, int prefix);
int create_socket(int type, int reuse);
pid_t gettid();
int read_size(uint8_t *buffer);
void write_size(uint8_t *buffer, int len);

#endif // for #ifndef UTIL_H
