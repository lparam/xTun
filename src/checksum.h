#ifndef _CHECKSUM_H
#define _CHECKSUM_H

uint16_t checksum(uint16_t *addr, int len);
uint16_t udp_checksum(struct iphdr *iph, struct udphdr *udph, uint8_t *payload, int payloadlen);

#endif // for #ifndef _CHECKSUM_H
