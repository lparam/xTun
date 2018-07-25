#include <string.h>
#include <assert.h>

#include "util.h"
#include "packet.h"


int
packet_parse(buffer_t *buf, struct packet *packet, cipher_ctx_t *ctx) {
    int off = 0;
    buffer_t tmp;
    for (;;) {
        if (buf->off == 0) {

        }

        size_t hdrsz = cipher_overhead(ctx) + PACKET_HEADER_BYTES;
        if (buf->len - off < hdrsz) {
            return PACKET_UNCOMPLETE;
        }

        uint8_t hdrbuf[hdrsz];
        memcpy(hdrbuf, buf->data, hdrsz);
        tmp.data = hdrbuf;
        tmp.len = hdrsz;

        if (crypto_decrypt(&tmp, ctx)) {
            printf("%s - 1 len: %ld\n", __func__, hdrsz);
            dump_hex(buf->data, hdrsz, "hdr");
            return PACKET_INVALID;
        }
        assert(tmp.len == PACKET_HEADER_BYTES);

        int size = read_size(tmp.data);
        if (size > PACKET_BUFFER_SIZE || size <= CRYPTO_MIN_OVERHEAD) {
            printf("%s - 2\n", __func__);
            return PACKET_INVALID;
        }

        off += hdrsz;

        if (buf->len - off < size) {
            return PACKET_UNCOMPLETE;
        }

        tmp.data = buf->data + off;
        tmp.len = size;
        if (crypto_decrypt(&tmp, ctx)) {
            printf("%s - 3 off: %d len: %d\n", __func__, off, size);
            return PACKET_INVALID;
        }
        packet->buf = tmp.data;
        packet->size = tmp.len;

        off += size;
        buf->off = off;

        return PACKET_COMPLETED;
    }
}

void
packet_reset(packet_t *packet) {
    packet->buf = NULL;
    packet->size = 0;
}