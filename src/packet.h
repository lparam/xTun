#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "crypto.h"

#define PACKET_UNCOMPLETE 0
#define PACKET_INVALID    1
#define PACKET_COMPLETED  2

#define PACKET_HEADER_BYTES    2
#define PACKET_BUFFER_SIZE     2048

typedef struct packet {
    uint16_t size;
    uint8_t *buf;
} packet_t;

int packet_parse(packet_t *packet, buffer_t *buf, cipher_ctx_t *ctx);
void packet_reset(packet_t *packet);

#endif // for #ifndef PACKET_H