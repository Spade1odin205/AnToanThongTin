/*
 * aes_core.c — AES-128 Core Implementation
 *
 * Implements:
 *   - Key Expansion (Key Schedule)
 *   - Single-block Encrypt / Decrypt
 *
 * These functions are thread-safe (read-only on AES_CTX after setup)
 * and are called by both sequential and parallel variants.
 */

#include <string.h>
#include "aes.h"
#include "aes_tables.h"

/* =========================================================
 * Internal: State operations
 *
 * AES state is a 4×4 matrix of bytes.
 * Per FIPS 197: state[row][col], where byte index = row + 4*col.
 * So in[0]=state[0][0], in[1]=state[1][0], in[2]=state[2][0],
 *    in[3]=state[3][0], in[4]=state[0][1], ...
 * ========================================================= */

typedef uint8_t State[4][4];  /* state[row][col] */

/* in[r + 4*c] = state[r][c] */
static void bytes_to_state(const uint8_t *in, State s)
{
    int r, c;
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            s[r][c] = in[r + 4 * c];
}

/* out[r + 4*c] = state[r][c] */
static void state_to_bytes(const State s, uint8_t *out)
{
    int r, c;
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            out[r + 4 * c] = s[r][c];
}

/* =========================================================
 * Key Expansion
 * Expands 16-byte key into 11 round keys (176 bytes).
 * ========================================================= */
void aes_key_expansion(AES_CTX *ctx, const uint8_t *key)
{
    uint8_t *rk = ctx->round_keys;
    int i;

    /* Copy original key as first round key */
    memcpy(rk, key, AES_KEY_SIZE);

    for (i = 4; i < 4 * (AES_ROUNDS + 1); i++) {
        uint8_t temp[4];
        memcpy(temp, &rk[(i - 1) * 4], 4);

        if (i % 4 == 0) {
            /* RotWord: rotate left by 1 byte */
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2];
            temp[2] = temp[3]; temp[3] = t;

            /* SubWord: apply S-box to each byte */
            temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];

            /* XOR with Rcon */
            temp[0] ^= rcon[i / 4];
        }

        /* rk[i] = rk[i-4] XOR temp */
        rk[i*4+0] = rk[(i-4)*4+0] ^ temp[0];
        rk[i*4+1] = rk[(i-4)*4+1] ^ temp[1];
        rk[i*4+2] = rk[(i-4)*4+2] ^ temp[2];
        rk[i*4+3] = rk[(i-4)*4+3] ^ temp[3];
    }
}

/* =========================================================
 * AddRoundKey
 * XOR state with a specific round key (16 bytes).
 * rk[r + 4*c] corresponds to state[r][c]
 * ========================================================= */
static void add_round_key(State s, const uint8_t *rk)
{
    int r, c;
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            s[r][c] ^= rk[r + 4 * c];
}

/* =========================================================
 * SubBytes — Forward
 * Apply S-box substitution to every byte.
 * ========================================================= */
static void sub_bytes(State s)
{
    int r, c;
    for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++)
            s[r][c] = sbox[s[r][c]];
}

/* =========================================================
 * SubBytes — Inverse
 * ========================================================= */
static void inv_sub_bytes(State s)
{
    int r, c;
    for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++)
            s[r][c] = inv_sbox[s[r][c]];
}

/* =========================================================
 * ShiftRows — Forward
 * Row r is shifted LEFT by r positions (across columns).
 * state[r][c] → state[r][(c - r + 4) % 4]
 * ========================================================= */
static void shift_rows(State s)
{
    uint8_t t;

    /* Row 0: no shift */

    /* Row 1: shift left by 1 column */
    t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2];
    s[1][2] = s[1][3]; s[1][3] = t;

    /* Row 2: shift left by 2 columns */
    t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
    t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;

    /* Row 3: shift left by 3 columns (= shift right by 1) */
    t = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1];
    s[3][1] = s[3][0]; s[3][0] = t;
}

/* =========================================================
 * ShiftRows — Inverse
 * Row r is shifted RIGHT by r positions (across columns).
 * ========================================================= */
static void inv_shift_rows(State s)
{
    uint8_t t;

    /* Row 0: no shift */

    /* Row 1: shift right by 1 column */
    t = s[1][3]; s[1][3] = s[1][2]; s[1][2] = s[1][1];
    s[1][1] = s[1][0]; s[1][0] = t;

    /* Row 2: shift right by 2 columns */
    t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
    t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;

    /* Row 3: shift right by 3 columns (= shift left by 1) */
    t = s[3][0]; s[3][0] = s[3][1]; s[3][1] = s[3][2];
    s[3][2] = s[3][3]; s[3][3] = t;
}

/* =========================================================
 * MixColumns — Forward
 * Each COLUMN is multiplied by matrix:
 *   [2 3 1 1]
 *   [1 2 3 1]
 *   [1 1 2 3]
 *   [3 1 1 2]
 * Column c: s[0][c], s[1][c], s[2][c], s[3][c]
 * ========================================================= */
static void mix_columns(State s)
{
    int c;
    uint8_t s0, s1, s2, s3;
    uint8_t h0, h1, h2, h3;

    for (c = 0; c < 4; c++) {
        s0 = s[0][c]; s1 = s[1][c];
        s2 = s[2][c]; s3 = s[3][c];

        h0 = xtime(s0); h1 = xtime(s1);
        h2 = xtime(s2); h3 = xtime(s3);

        s[0][c] = h0 ^ (s1 ^ h1) ^ s2 ^ s3;        /* 2·s0 + 3·s1 + s2  + s3  */
        s[1][c] = s0 ^ h1 ^ (s2 ^ h2) ^ s3;        /* s0  + 2·s1 + 3·s2 + s3  */
        s[2][c] = s0 ^ s1 ^ h2 ^ (s3 ^ h3);        /* s0  + s1  + 2·s2 + 3·s3 */
        s[3][c] = (s0 ^ h0) ^ s1 ^ s2 ^ h3;        /* 3·s0 + s1  + s2  + 2·s3 */
    }
}

/* =========================================================
 * MixColumns — Inverse
 * Multiply by inverse matrix with coefficients 0x0e,0x0b,0x0d,0x09
 * ========================================================= */
static void inv_mix_columns(State s)
{
    int c;
    uint8_t s0, s1, s2, s3;

    for (c = 0; c < 4; c++) {
        s0 = s[0][c]; s1 = s[1][c];
        s2 = s[2][c]; s3 = s[3][c];

        s[0][c] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        s[1][c] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        s[2][c] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        s[3][c] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

/* =========================================================
 * aes_encrypt_block
 * Encrypts exactly 16 bytes (in → out).
 * AES_CTX must be initialized with aes_key_expansion() first.
 * Thread-safe: ctx is read-only.
 * ========================================================= */
void aes_encrypt_block(const AES_CTX *ctx, const uint8_t *in, uint8_t *out)
{
    State state;
    const uint8_t *rk = ctx->round_keys;
    int round;

    bytes_to_state(in, state);
    add_round_key(state, rk);          /* Initial round key add */

    for (round = 1; round < AES_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk + round * 16);
    }

    /* Final round: no MixColumns */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk + AES_ROUNDS * 16);

    state_to_bytes(state, out);
}

/* =========================================================
 * aes_decrypt_block
 * Decrypts exactly 16 bytes (in → out).
 * Thread-safe: ctx is read-only.
 * ========================================================= */
void aes_decrypt_block(const AES_CTX *ctx, const uint8_t *in, uint8_t *out)
{
    State state;
    const uint8_t *rk = ctx->round_keys;
    int round;

    bytes_to_state(in, state);
    add_round_key(state, rk + AES_ROUNDS * 16);  /* Start from last round key */

    for (round = AES_ROUNDS - 1; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rk + round * 16);
        inv_mix_columns(state);
    }

    /* Final (first) round */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, rk);

    state_to_bytes(state, out);
}

/* =========================================================
 * Utility functions
 * ========================================================= */
#include <stdio.h>

void aes_print_block(const char *label, const uint8_t *block, size_t len)
{
    size_t i;
    printf("%-20s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x ", block[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n%22s", "");
    }
    printf("\n");
}

int aes_verify_block(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
