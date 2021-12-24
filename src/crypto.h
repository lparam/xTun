#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "buffer.h"

#define CRYPTO_MIN_OVERHEAD 16
#define CRYPTO_MAX_OVERHEAD 42
#define CRYPTO_UDP_MIN_OVERHEAD 24

typedef struct cipher_ctx cipher_ctx_t;

int crypto_init(const char *password);
int crypto_encrypt(buffer_t *plaintext, cipher_ctx_t *ctx);
int crypto_decrypt(buffer_t *ciphertext, cipher_ctx_t *ctx);
int crypto_encrypt_with_new_salt(buffer_t *plaintext, cipher_ctx_t *ctx);
int crypto_decrypt_with_new_salt(buffer_t *ciphertext, cipher_ctx_t *ctx);

cipher_ctx_t * cipher_new();
void cipher_free(cipher_ctx_t *ctx);
void cipher_reset(cipher_ctx_t *ctx);
size_t cipher_overhead(cipher_ctx_t *ctx);

#endif