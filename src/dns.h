#ifndef _DNS_H
#define _DNS_H

#include <resolv.h>

int dns_init(const char *path);
void dns_destroy();
int dns_pasre_query(uint8_t *buf, int buflen);
int dns_filter_query(uint8_t *buf, int buflen);

int local_ns_initparse(const unsigned char *msg, int msglen, ns_msg *handle);
int local_ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr);

#endif // for #ifndef _DNS_H
