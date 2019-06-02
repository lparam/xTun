#ifndef _ANDROID_H
#define _ANDROID_H

#include "buffer.h"

int protect_socket(int fd);
int handle_local_dns_query(int tunfd,struct sockaddr *dns_server, buffer_t *buf);
void clear_dns_query();

#endif // for #ifndef _ANDROID_H
