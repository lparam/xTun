#include <string.h>

#include "util.h"
#include "packet.h"
#include "tun.h"

int
packet_parse(packet_t *packet, buffer_t *buf, cipher_ctx_t *ctx) {
    buffer_t tmp;

    if (packet->size == 0) {
        size_t hdrsz = cipher_overhead(ctx) + PACKET_HEADER_BYTES;
        if (buf->len < hdrsz) {
            return PACKET_UNCOMPLETE;
        }

        tmp.data = buf->data;
        tmp.len = hdrsz;
        if (crypto_decrypt(&tmp, ctx)) {
            return PACKET_INVALID;
        }

        packet->size = read_size(tmp.data);
        if (packet->size > PACKET_BUFFER_SIZE || packet->size <= CRYPTO_MIN_OVERHEAD) {
            return PACKET_INVALID;
        }

        buf->off += hdrsz;
    }

    if (buf->len - buf->off < packet->size) {
        return PACKET_UNCOMPLETE;
    }

    tmp.data = buf->data + buf->off;
    tmp.len = packet->size;
    buf->off += packet->size;
    if (crypto_decrypt(&tmp, ctx)) {
        return PACKET_INVALID;
    }
    packet->buf = tmp.data;
    packet->size = tmp.len;

    return PACKET_COMPLETED;
}

void
packet_reset(packet_t *packet) {
    packet->buf = NULL;
    packet->size = 0;
}