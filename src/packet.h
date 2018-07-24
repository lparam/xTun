#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdlib.h>

#include "uv.h"

#include "buffer.h"
#include "crypto.h"


#define HEADER_BYTES    2
// #define PRIMITIVE_BYTES 24
// #define OVERHEAD_BYTES  26

#define PACKET_UNCOMPLETE 0
#define PACKET_INVALID    1
#define PACKET_COMPLETED  2

#define PACKET_BUFFER_SIZE (64 * 1024)

typedef struct packet {
    uint16_t size;
    uint8_t *buf;
} packet_t;

int packet_parse(buffer_t *buf, struct packet *packet, cipher_ctx_t *ctx);

#endif // for #ifndef PACKET_H
