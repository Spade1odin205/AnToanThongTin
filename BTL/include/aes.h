#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* =========================================================
 * AES-128 Constants
 * ========================================================= */
#define AES_BLOCK_SIZE     16   /* bytes per block         */
#define AES_KEY_SIZE       16   /* AES-128 key size        */
#define AES_ROUNDS         10   /* AES-128 number of rounds*/
#define AES_KEY_EXP_SIZE  176   /* 11 round keys × 16 bytes*/

/* =========================================================
 * AES Context
 * ========================================================= */
typedef struct {
    uint8_t round_keys[AES_KEY_EXP_SIZE]; /* expanded round keys */
} AES_CTX;

/* =========================================================
 * Core AES Functions (aes_core.c)
 * ========================================================= */
void aes_key_expansion(AES_CTX *ctx, const uint8_t *key);
void aes_encrypt_block(const AES_CTX *ctx, const uint8_t *in, uint8_t *out);
void aes_decrypt_block(const AES_CTX *ctx, const uint8_t *in, uint8_t *out);

/* =========================================================
 * Sequential Modes (aes_sequential.c)
 * ========================================================= */
void aes_ecb_encrypt_seq(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out, size_t len);
void aes_ecb_decrypt_seq(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out, size_t len);
void aes_cbc_encrypt_seq(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len);
void aes_cbc_decrypt_seq(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len);

/* =========================================================
 * Parallel Modes — OpenMP (aes_parallel.c)
 * ========================================================= */
void aes_ecb_encrypt_par(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads);
void aes_ecb_decrypt_par(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads);
void aes_cbc_encrypt_par(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads);
void aes_cbc_decrypt_par(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads);

/* =========================================================
 * Utility
 * ========================================================= */
void aes_print_block(const char *label, const uint8_t *block, size_t len);
int  aes_verify_block(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* AES_H */
