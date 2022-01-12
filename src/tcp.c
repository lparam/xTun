#include "stdlib.h"
#include "string.h"
#include "assert.h"

#include "uv.h"

#include "logger.h"
#include "crypto.h"
#include "packet.h"
#include "util.h"
#include "tun.h"

static void
send_cb(uv_write_t *req, int status) {
    uv_buf_t *buf_hdr = (uv_buf_t *) (req + 1);
    uv_buf_t *buf_data = buf_hdr + 1;
    buffer_t *hdr = container_of(&buf_hdr->base, buffer_t, data);
    buffer_t *data = container_of(&buf_data->base, buffer_t, data);
    buffer_free(hdr);
    buffer_free(data);
    free(req);
}

int
tcp_send(uv_stream_t *stream, buffer_t *buf, cipher_ctx_t *ctx) {
    buffer_t hdr;
    buffer_alloc(&hdr, CRYPTO_MAX_OVERHEAD);
    write_size(hdr.data, buf->len + CRYPTO_MIN_OVERHEAD);
    hdr.len = PACKET_HEADER_BYTES;

    int rc = crypto_encrypt(&hdr, ctx);
    assert(rc == 0);
    rc = crypto_encrypt(buf, ctx);
    assert(rc == 0);

    uv_write_t *req = malloc(sizeof(*req) + sizeof(uv_buf_t) * 2);

    uv_buf_t *buf_hdr = (uv_buf_t *) (req + 1);
    uv_buf_t *buf_data = buf_hdr + 1;
    *buf_hdr = uv_buf_init((char *) hdr.data, hdr.len);
    *buf_data = uv_buf_init((char *) buf->data, buf->len);

    uv_buf_t bufs[] = {
        *buf_hdr,
        *buf_data,
    };

    rc = uv_write(req, stream, bufs, 2, send_cb);
    if (rc) {
        logger_log(LOG_ERR, "TCP Write error (%s)", uv_strerror(rc));
        buffer_free(&hdr);
        buffer_free(buf);
        free(req);
    }
    return rc;
}
