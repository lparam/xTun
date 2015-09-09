#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "uv.h"

#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))

void dump_hex(const void *data, uint32_t len, char *title);
int resolve_addr(const char *buf, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);

#endif // for #ifndef UTIL_H
