#ifndef _DNS_H
#define _DNS_H

int dns_init(const char *path);
void dns_destroy();
int filter_query(uint8_t *buf, int buflen);

#endif // for #ifndef _DNS_H
