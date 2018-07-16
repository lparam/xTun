#ifndef PACKET_H
#define PACKET_H

#include "uv.h"
#include <stdint.h>
#include <stdlib.h>


#define HEADER_BYTES    2
#define PRIMITIVE_BYTES 24
#define OVERHEAD_BYTES  26

#define PACKET_UNCOMPLETE 0
#define PACKET_INVALID    1
#define PACKET_COMPLETED  2

#define PACKET_BUFFER_SIZE (64 * 1024)

typedef struct {
    int off;
    int len;
    uint8_t data[PACKET_BUFFER_SIZE];
} buffer_t;

typedef struct packet {
    uint16_t size;
    uint8_t *buf;
} packet_t;

int packet_parse(buffer_t *buf, struct packet *packet);

#endif // for #ifndef PACKET_H
