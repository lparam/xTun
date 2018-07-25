#include "stdlib.h"
#include "string.h"
#include "assert.h"

#include "uv.h"

#include "logger.h"
#include "crypto.h"
#include "packet.h"
#include "util.h"

static void
send_cb(uv_write_t *req, int status) {
    uv_buf_t *buf1 = (uv_buf_t *) (req + 1);
    uv_buf_t *buf2 = buf1 + 1;
    buffer_t *buffer1 = container_of(&buf1->base, buffer_t, data);
    buffer_t *buffer2 = container_of(&buf2->base, buffer_t, data);
    buffer_free(buffer1);
    buffer_free(buffer2);
    free(req);
}

void
tcp_send(uv_stream_t *stream, buffer_t *buf, cipher_ctx_t *ctx) {
    buffer_t hdr;
    buffer_alloc(&hdr, HEADER_BYTES);
    write_size(hdr.data, buf->len + CRYPTO_MIN_OVERHEAD);
    hdr.len = HEADER_BYTES;

    int rc = crypto_encrypt(&hdr, ctx);
    assert(rc == 0);
    rc = crypto_encrypt(buf, ctx);
    assert(rc == 0);

    uv_write_t *req = malloc(sizeof(*req) + sizeof(uv_buf_t) * 2);

    uv_buf_t *outbuf1 = (uv_buf_t *) (req + 1);
    uv_buf_t *outbuf2 = outbuf1 + 1;
    *outbuf1 = uv_buf_init((char *) hdr.data, hdr.len);
    *outbuf2 = uv_buf_init((char *) buf->data, buf->len);

    // dump_hex(hdr.data, hdr.len, "hdr");
    // dump_hex(buf->data, buf->len, "data");

    uv_buf_t bufs[2] = {
        *outbuf1,
        *outbuf2,
    };

    rc = uv_write(req, stream, bufs, 2, send_cb);
    if (rc) {
        logger_log(LOG_ERR, "TCP Write error (%s)", uv_strerror(rc));
        buffer_free(&hdr);
        buffer_free(buf);
        free(req);
    }
}
