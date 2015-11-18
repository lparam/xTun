#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


struct ipv4_pseudo {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t zeros;
    uint8_t protocol;
    uint16_t len;
};


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t checksum = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    checksum = ~sum;

    return (checksum);
}

uint16_t
udp_checksum(struct iphdr *iph, struct udphdr *udph, uint8_t *payload, int payloadlen) {
    struct ipv4_pseudo pseudo;
    uint8_t *buffer;
    size_t len, udp_len, total_len;
    uint16_t cksum;

    len = sizeof(struct ipv4_pseudo);
    udp_len = sizeof(struct udphdr);
    total_len = len + udp_len + payloadlen;

    /* fill ip pseudo header */
    pseudo.src_addr = iph->saddr;
    pseudo.dest_addr = iph->daddr;
    pseudo.zeros = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.len = htons(udp_len + payloadlen);

    /* create a temporary buffer, stuff it with data and compute the checksum
     * for the whole thing
     */
    buffer = (uint8_t *) malloc(total_len);
    memcpy(buffer, &pseudo, len);
    memcpy(buffer + len, udph, udp_len);
    memcpy(buffer + len + udp_len, payload, payloadlen);
    cksum = checksum((uint16_t *) buffer, total_len);

    free(buffer);

    return cksum;
}
