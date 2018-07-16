#include <string.h>
#include <assert.h>

#include "util.h"
#include "packet.h"


int
packet_parse(buffer_t *buf, struct packet *packet) {
    int off = 0;
    for (;;) {
        if (buf->len - off < HEADER_BYTES) {
            return PACKET_UNCOMPLETE;
        }

        off += 2;
        uint16_t size = read_size(buf->data);
        if (size > 10000) {
            return PACKET_INVALID;
        }
        if (buf->len - off < size) {
            return PACKET_UNCOMPLETE;
        }

        // TODO: parse all packet
        packet->size = size;
        packet->buf = buf->data + off;

        off += size;
        buf->off = off;

        return PACKET_COMPLETED;
    }
}
