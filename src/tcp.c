#include "stdlib.h"
#include "string.h"

#include "uv.h"

#include "logger.h"
#include "crypto.h"
#include "packet.h"
#include "util.h"

static void
send_cb(uv_write_t *req, int status) {
    uv_buf_t *buf1 = (uv_buf_t *) (req + 1);
    uv_buf_t *buf2 = buf1 + 1;
    free(buf1->base);
    free(buf2->base);
    free(req);
}

void
tcp_send(uv_stream_t *stream, buffer_t *buf, cipher_ctx_t *ctx) {
    buffer_t hdr;
    buffer_alloc(&hdr, HEADER_BYTES);
    write_size(hdr.data, buf->len + CRYPTO_MIN_OVERHEAD);
    hdr.len = HEADER_BYTES;

    crypto_encrypt(&hdr, ctx);
    crypto_encrypt(buf, ctx);

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

    int rc = uv_write(req, stream, bufs, 2, send_cb);
    if (rc) {
        logger_log(LOG_ERR, "TCP Write error (%s)", uv_strerror(rc));
        buffer_free(&hdr);
        buffer_free(buf);
        free(req);
    }
}
