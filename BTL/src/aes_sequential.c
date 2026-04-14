/*
 * aes_sequential.c — Sequential (Single-threaded) AES Modes
 *
 * Implements ECB and CBC using a simple loop over 16-byte blocks.
 * No parallelism. Used as baseline for benchmark comparison.
 */

#include <string.h>
#include "aes.h"

/* =========================================================
 * ECB (Electronic Codebook) — Sequential
 *
 * Each 16-byte block is encrypted/decrypted independently.
 * Identical plaintext blocks → identical ciphertext (no IV).
 *
 *   len must be a multiple of AES_BLOCK_SIZE.
 * ========================================================= */

void aes_ecb_encrypt_seq(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    size_t num_blocks = len / AES_BLOCK_SIZE;

    for (i = 0; i < num_blocks; i++) {
        aes_encrypt_block(ctx,
                          in  + i * AES_BLOCK_SIZE,
                          out + i * AES_BLOCK_SIZE);
    }
}

void aes_ecb_decrypt_seq(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    size_t num_blocks = len / AES_BLOCK_SIZE;

    for (i = 0; i < num_blocks; i++) {
        aes_decrypt_block(ctx,
                          in  + i * AES_BLOCK_SIZE,
                          out + i * AES_BLOCK_SIZE);
    }
}

/* =========================================================
 * CBC (Cipher Block Chaining) — Sequential
 *
 * Encrypt: C[i] = Encrypt(P[i] XOR C[i-1]),  C[-1] = IV
 * Decrypt: P[i] = Decrypt(C[i]) XOR C[i-1],  C[-1] = IV
 *
 * CBC encryption is INHERENTLY sequential (each block depends
 * on the previous ciphertext), but decryption CAN be parallelized.
 * ========================================================= */

void aes_cbc_encrypt_seq(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i, b;
    size_t num_blocks = len / AES_BLOCK_SIZE;
    uint8_t xored[AES_BLOCK_SIZE];
    const uint8_t *prev = iv;  /* previous ciphertext block */

    for (i = 0; i < num_blocks; i++) {
        /* XOR plaintext with previous ciphertext (or IV) */
        for (b = 0; b < AES_BLOCK_SIZE; b++)
            xored[b] = in[i * AES_BLOCK_SIZE + b] ^ prev[b];

        /* Encrypt the XOR result */
        aes_encrypt_block(ctx, xored, out + i * AES_BLOCK_SIZE);
        prev = out + i * AES_BLOCK_SIZE;
    }
}

void aes_cbc_decrypt_seq(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i, b;
    size_t num_blocks = len / AES_BLOCK_SIZE;
    uint8_t decrypted[AES_BLOCK_SIZE];

    for (i = 0; i < num_blocks; i++) {
        /* Decrypt ciphertext block */
        aes_decrypt_block(ctx, in + i * AES_BLOCK_SIZE, decrypted);

        /* XOR with previous ciphertext block (or IV) */
        const uint8_t *prev = (i == 0) ? iv : in + (i - 1) * AES_BLOCK_SIZE;
        for (b = 0; b < AES_BLOCK_SIZE; b++)
            out[i * AES_BLOCK_SIZE + b] = decrypted[b] ^ prev[b];
    }
}
