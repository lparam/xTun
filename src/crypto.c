#include <string.h>
#include <assert.h>
#include "sodium.h"
#include "crypto.h"
#include "buffer.h"
#include "util.h"

/*
 *
 * TCP Cipher Text
 * +--------+------------+-----------+-------------+
 * | length | length mac |  payload  | payload mac |
 * +--------+------------+-----------+-------------+
 * |   2    |     16     |  Variable |      16     |
 * +--------+------------+-----------+-------------+
 *
 */

/*
 *
 * UDP Cipher Text
 * +------------+-----------+-------------+
 * |    salt    |  payload  | payload mac |
 * +------------+-----------+-------------+
 * |     8      |  Variable |      16     |
 * +------------+-----------+-------------+
 *
 */

#define SALT_LENGTH 8

typedef struct cipher_ctx {
    uint32_t init;
    uint8_t salt[SALT_LENGTH];
    uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
} cipher_ctx_t;

#define SUBKEY_CONTEXT "xTun-subkey"

#if !(crypto_kdf_KEYBYTES >= crypto_generichash_BYTES_MIN && crypto_kdf_KEYBYTES <= crypto_generichash_BYTES_MAX)
#error "invalid generichash key bytes"
#endif

static uint8_t master_key[crypto_kdf_KEYBYTES];

cipher_ctx_t *
cipher_new() {
    struct cipher_ctx *ctx = malloc(sizeof *ctx);
    sodium_memzero(ctx, sizeof(*ctx));
    return ctx;
}

void
cipher_free(cipher_ctx_t *ctx) {
    free(ctx);
}

void
cipher_reset(cipher_ctx_t *ctx) {
    sodium_memzero(ctx, sizeof(*ctx));
}

inline size_t
cipher_overhead(cipher_ctx_t *ctx) {
    if (ctx->init) {
        return crypto_aead_chacha20poly1305_ietf_ABYTES;
    }
    return SALT_LENGTH + crypto_aead_chacha20poly1305_ietf_ABYTES;
}

static int
cipher_ctx_derive_key(cipher_ctx_t *ctx) {
    uint64_t id = (uint64_t)(ctx->salt[0]) |
                  (uint64_t)(ctx->salt[1]) << 8 |
                  (uint64_t)(ctx->salt[2]) << 16 |
                  (uint64_t)(ctx->salt[3]) << 24 |
                  (uint64_t)(ctx->salt[4]) << 32 |
                  (uint64_t)(ctx->salt[5]) << 40 |
                  (uint64_t)(ctx->salt[6]) << 48 |
                  (uint64_t)(ctx->salt[7]) << 56;
    return crypto_kdf_derive_from_key(ctx->key, sizeof ctx->key, id,
                                      SUBKEY_CONTEXT, master_key);
}

static int
encrypt(buffer_t *plaintext, cipher_ctx_t *ctx, int reset) {
    size_t salt_off = 0;

    if (!ctx->init || reset) {
        salt_off = SALT_LENGTH;
    }

    size_t clen = salt_off + plaintext->len + crypto_aead_chacha20poly1305_IETF_ABYTES;
    uint8_t ciphertext[clen];

    if (!ctx->init || reset) {
        randombytes_buf(ctx->salt, SALT_LENGTH);
        memcpy(ciphertext, ctx->salt, SALT_LENGTH);
        memset(ctx->nonce, 0, sizeof ctx->nonce);
        cipher_ctx_derive_key(ctx);
        ctx->init = 1;
    }

    // dump_hex(ctx->key, sizeof ctx->key, "encrypt key");
    unsigned long long long_clen = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext + salt_off, &long_clen,
                                                       plaintext->data, plaintext->len, NULL, 0, NULL,
                                                       ctx->nonce, ctx->key);
    assert(long_clen == clen - salt_off);
    sodium_increment(ctx->nonce, sizeof ctx->nonce);

    buffer_realloc(plaintext, clen, clen);
    memcpy(plaintext->data, ciphertext, clen);
    if (plaintext->len == 2) {
        dump_hex(ciphertext, clen, "hdr encrypt");
    }
    plaintext->len = clen;

    return rc;
}

static int
decrypt(buffer_t *ciphertext, cipher_ctx_t *ctx, int reset) {
    size_t salt_off = 0;

    if (!ctx->init || reset) {
        memcpy(ctx->salt, ciphertext->data, SALT_LENGTH);
        memset(ctx->nonce, 0, sizeof ctx->nonce);
        cipher_ctx_derive_key(ctx);
        salt_off = SALT_LENGTH;
        ctx->init = 1;
    }

    size_t mlen = ciphertext->len - salt_off - crypto_aead_chacha20poly1305_IETF_ABYTES;
    if (mlen == 2) {
        dump_hex(ciphertext->data, ciphertext->len, "hdr decrypt");
    }

    // dump_hex(ctx->key, sizeof ctx->key, "decrypt key");
    unsigned long long long_mlen = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext->data, &long_mlen, NULL,
                                                       ciphertext->data + salt_off, ciphertext->len - salt_off, NULL, 0,
                                                       ctx->nonce, ctx->key);
    if (rc) {
        return -1;
    }

    assert(long_mlen == mlen);
    sodium_increment(ctx->nonce, sizeof ctx->nonce);

    ciphertext->len = mlen;

    return 0;
}

int
crypto_init(const char *password) {
    return crypto_generichash(master_key, sizeof master_key,
                              (uint8_t*)password, strlen(password), NULL, 0);

}

int
crypto_encrypt(buffer_t *plaintext, cipher_ctx_t *ctx) {
    return encrypt(plaintext, ctx, 0);
}

int
crypto_decrypt(buffer_t *ciphertext, cipher_ctx_t *ctx) {
    return decrypt(ciphertext, ctx, 0);
}

int
crypto_encrypt_with_new_salt(buffer_t *plaintext, cipher_ctx_t *ctx) {
    return encrypt(plaintext, ctx, 1);
}

int
crypto_decrypt_with_new_salt(buffer_t *ciphertext, cipher_ctx_t *ctx) {
    return decrypt(ciphertext, ctx, 1);
}