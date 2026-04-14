/*
 * bench_csv.c — Benchmark nhỏ gọn, xuất kết quả dạng CSV
 *
 * Chỉ đo ECB (encrypt/decrypt) với các kích thước vừa phải
 * để hoàn thành nhanh, phục vụ vẽ biểu đồ speedup.
 *
 * Compile: make bench_csv
 * Usage:   ./bench_csv <num_threads> >> results.csv
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>
#include "aes.h"

#define ITERATIONS 3   /* Ít lần hơn để chạy nhanh */

static const uint8_t KEY[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static double measure_ecb_enc_seq(const AES_CTX *ctx, uint8_t *in, uint8_t *out, size_t len) {
    double t = now_ms();
    for (int i = 0; i < ITERATIONS; i++) {
        size_t nb = len / 16;
        for (size_t b = 0; b < nb; b++)
            aes_encrypt_block(ctx, in + b*16, out + b*16);
    }
    return (now_ms() - t) / ITERATIONS;
}

static double measure_ecb_enc_par(const AES_CTX *ctx, uint8_t *in, uint8_t *out,
                                   size_t len, int threads) {
    size_t nb = len / 16;
    long long b;
    double t = now_ms();
    for (int i = 0; i < ITERATIONS; i++) {
        #pragma omp parallel for schedule(static) num_threads(threads) \
            shared(ctx, in, out) firstprivate(nb) default(none)
        for (b = 0; b < (long long)nb; b++)
            aes_encrypt_block(ctx, in + b*16, out + b*16);
    }
    return (now_ms() - t) / ITERATIONS;
}

static double measure_ecb_dec_seq(const AES_CTX *ctx, uint8_t *in, uint8_t *out, size_t len) {
    double t = now_ms();
    for (int i = 0; i < ITERATIONS; i++) {
        size_t nb = len / 16;
        for (size_t b = 0; b < nb; b++)
            aes_decrypt_block(ctx, in + b*16, out + b*16);
    }
    return (now_ms() - t) / ITERATIONS;
}

static double measure_ecb_dec_par(const AES_CTX *ctx, uint8_t *in, uint8_t *out,
                                   size_t len, int threads) {
    size_t nb = len / 16;
    long long b;
    double t = now_ms();
    for (int i = 0; i < ITERATIONS; i++) {
        #pragma omp parallel for schedule(static) num_threads(threads) \
            shared(ctx, in, out) firstprivate(nb) default(none)
        for (b = 0; b < (long long)nb; b++)
            aes_decrypt_block(ctx, in + b*16, out + b*16);
    }
    return (now_ms() - t) / ITERATIONS;
}

static double measure_cbc_dec_par(const AES_CTX *ctx, const uint8_t *iv,
                                   uint8_t *in, uint8_t *out, size_t len, int threads) {
    size_t nb = len / 16;
    long long i;
    double t = now_ms();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        #pragma omp parallel for schedule(static) num_threads(threads) \
            shared(ctx, in, out, iv) firstprivate(nb) default(none)
        for (i = 0; i < (long long)nb; i++) {
            uint8_t tmp[16];
            size_t b;
            aes_decrypt_block(ctx, in + i*16, tmp);
            const uint8_t *prev = (i == 0) ? iv : in + (i-1)*16;
            for (b = 0; b < 16; b++)
                out[i*16 + b] = tmp[b] ^ prev[b];
        }
    }
    return (now_ms() - t) / ITERATIONS;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        return 1;
    }
    int threads = atoi(argv[1]);

    /* Kích thước test: 512KB, 1MB, 2MB, 4MB, 8MB, 16MB */
    static const size_t SIZES[] = {
        512*1024, 1024*1024, 2*1024*1024,
        4*1024*1024, 8*1024*1024, 16*1024*1024
    };
    static const int N = 6;

    const uint8_t iv[16] = {0};
    AES_CTX ctx;
    aes_key_expansion(&ctx, KEY);

    /* Header CSV (chỉ in một lần nếu file trống) */
    /* Caller phải print header nếu cần */

    uint8_t *in  = malloc(SIZES[N-1]);
    uint8_t *out = malloc(SIZES[N-1]);
    for (size_t i = 0; i < SIZES[N-1]; i++) in[i] = (uint8_t)(i & 0xFF);

    fprintf(stderr, "[bench_csv] threads=%d\n", threads);

    for (int s = 0; s < N; s++) {
        size_t sz = SIZES[s];
        double mb = sz / (1024.0 * 1024.0);

        double enc_seq = measure_ecb_enc_seq(&ctx, in, out, sz);
        double enc_par = measure_ecb_enc_par(&ctx, in, out, sz, threads);
        double dec_seq = measure_ecb_dec_seq(&ctx, in, out, sz);
        double dec_par = measure_ecb_dec_par(&ctx, in, out, sz, threads);
        double cbc_seq = measure_ecb_dec_seq(&ctx, in, out, sz);  /* baseline */
        double cbc_par = measure_cbc_dec_par(&ctx, iv, in, out, sz, threads);

        /* CSV: threads,mb,enc_seq,enc_par,enc_speedup,dec_seq,dec_par,dec_speedup,cbc_par,cbc_speedup */
        printf("%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
               threads, mb,
               enc_seq, enc_par, enc_seq / enc_par,
               dec_seq, dec_par, dec_seq / dec_par,
               cbc_par, cbc_seq / cbc_par);
        fflush(stdout);

        fprintf(stderr, "  %.1f MB done\n", mb);
    }

    free(in);
    free(out);
    return 0;
}
