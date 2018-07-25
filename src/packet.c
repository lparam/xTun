#include <string.h>
#include <assert.h>

#include "util.h"
#include "packet.h"


int
packet_parse(buffer_t *buf, struct packet *packet, cipher_ctx_t *ctx) {
    int off = 0;
    for (;;) {
        size_t len = cipher_overhead(ctx) + HEADER_BYTES;
        if (packet->size == 0) {
            if (buf->len - off < len) {
                return PACKET_UNCOMPLETE;
            }
            buffer_t tmp;
            tmp.data = buf->data;
            tmp.len = len;
            if (crypto_decrypt(&tmp, ctx)) {
                printf("%s - 1 len: %ld\n", __func__, len);
                return PACKET_INVALID;
            }

            packet->size = read_size(buf->data);
            if (packet->size > 10000 || packet->size <= CRYPTO_MIN_OVERHEAD) {
                printf("%s - 2\n", __func__);
                return PACKET_INVALID;
            }

            off += len;
        }

        if (buf->len - off < packet->size) {
            return PACKET_UNCOMPLETE;
        }

        packet->buf = buf->data + off;

        off += packet->size;
        buf->off = off;

        buffer_t tmp;
        tmp.data = packet->buf;
        tmp.len = packet->size;
        if (crypto_decrypt(&tmp, ctx)) {
                printf("%s - 3 off: %d len: %d\n", __func__, off, packet->size);
            return PACKET_INVALID;
        }
        packet->size = tmp.len;

        // TODO: parse all packet
        return PACKET_COMPLETED;
    }
}
