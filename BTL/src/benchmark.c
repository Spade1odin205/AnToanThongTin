/*
 * benchmark.c — AES Performance Benchmarking
 *
 * Measures time for sequential vs parallel AES using
 * high-resolution POSIX clock and prints formatted tables.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#include "benchmark.h"

#define BENCH_ITERATIONS 5   /* Số lần chạy để lấy trung bình */

/* =========================================================
 * bench_now_ms — Wall-clock time in milliseconds
 * ========================================================= */
double bench_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* =========================================================
 * Helper: allocate and fill buffer with pseudo-random data
 * ========================================================= */
static uint8_t *make_buffer(size_t size)
{
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return NULL;
    /* Fill with repeating pattern (not crypto-random, just for perf test) */
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)(i & 0xFF);
    return buf;
}

/* =========================================================
 * bench_ecb_encrypt
 * ========================================================= */
BenchReport bench_ecb_encrypt(const uint8_t *key, size_t data_size, int threads)
{
    BenchReport report;
    AES_CTX ctx;
    double   t_start, elapsed;
    int      iter;

    aes_key_expansion(&ctx, key);

    uint8_t *plain  = make_buffer(data_size);
    uint8_t *cipher = make_buffer(data_size);

    /* --- Sequential baseline --- */
    elapsed = 0;
    for (iter = 0; iter < BENCH_ITERATIONS; iter++) {
        t_start = bench_now_ms();
        aes_ecb_encrypt_seq(&ctx, plain, cipher, data_size);
        elapsed += bench_now_ms() - t_start;
    }
    report.seq.time_ms    = elapsed / BENCH_ITERATIONS;
    report.seq.throughput = (data_size / (1024.0 * 1024.0)) /
                             (report.seq.time_ms / 1000.0);

    /* --- Parallel --- */
    elapsed = 0;
    for (iter = 0; iter < BENCH_ITERATIONS; iter++) {
        t_start = bench_now_ms();
        aes_ecb_encrypt_par(&ctx, plain, cipher, data_size, threads);
        elapsed += bench_now_ms() - t_start;
    }
    report.par.time_ms    = elapsed / BENCH_ITERATIONS;
    report.par.throughput = (data_size / (1024.0 * 1024.0)) /
                             (report.par.time_ms / 1000.0);

    report.speedup    = report.seq.time_ms / report.par.time_ms;
    report.threads    = threads;
    report.data_size  = data_size;

    free(plain);
    free(cipher);
    return report;
}

/* =========================================================
 * bench_ecb_decrypt
 * ========================================================= */
BenchReport bench_ecb_decrypt(const uint8_t *key, size_t data_size, int threads)
{
    BenchReport report;
    AES_CTX ctx;
    double   t_start, elapsed;
    int      iter;

    aes_key_expansion(&ctx, key);

    uint8_t *cipher = make_buffer(data_size);
    uint8_t *plain  = make_buffer(data_size);

    /* --- Sequential --- */
    elapsed = 0;
    for (iter = 0; iter < BENCH_ITERATIONS; iter++) {
        t_start = bench_now_ms();
        aes_ecb_decrypt_seq(&ctx, cipher, plain, data_size);
        elapsed += bench_now_ms() - t_start;
    }
    report.seq.time_ms    = elapsed / BENCH_ITERATIONS;
    report.seq.throughput = (data_size / (1024.0 * 1024.0)) /
                             (report.seq.time_ms / 1000.0);

    /* --- Parallel --- */
    elapsed = 0;
    for (iter = 0; iter < BENCH_ITERATIONS; iter++) {
        t_start = bench_now_ms();
        aes_ecb_decrypt_par(&ctx, cipher, plain, data_size, threads);
        elapsed += bench_now_ms() - t_start;
    }
    report.par.time_ms    = elapsed / BENCH_ITERATIONS;
    report.par.throughput = (data_size / (1024.0 * 1024.0)) /
                             (report.par.time_ms / 1000.0);

    report.speedup    = report.seq.time_ms / report.par.time_ms;
    report.threads    = threads;
    report.data_size  = data_size;

    free(cipher);
    free(plain);
    return report;
}

/* =========================================================
 * bench_cbc_decrypt
 * ========================================================= */
BenchReport bench_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                               size_t data_size, int threads)
{
    BenchReport report;
    AES_CTX ctx;
    double   t_start, elapsed;
    int      iter;

    aes_key_expansion(&ctx, key);

    uint8_t *cipher = make_buffer(data_size);
    uint8_t *plain  = make_buffer(data_size);

    /* --- Sequential --- */
    elapsed = 0;
    for (iter = 0; iter < BENCH_ITERATIONS; iter++) {
        t_start = bench_now_ms();
        aes_cbc_decrypt_seq(&ctx, iv, cipher, plain, data_size);
        elapsed += bench_now_ms() - t_start;
    }
    report.seq.time_ms    = elapsed / BENCH_ITERATIONS;
    report.seq.throughput = (data_size / (1024.0 * 1024.0)) /
                             (report.seq.time_ms / 1000.0);

    /* --- Parallel --- */
    elapsed = 0;
    for (iter = 0; iter < BENCH_ITERATIONS; iter++) {
        t_start = bench_now_ms();
        aes_cbc_decrypt_par(&ctx, iv, cipher, plain, data_size, threads);
        elapsed += bench_now_ms() - t_start;
    }
    report.par.time_ms    = elapsed / BENCH_ITERATIONS;
    report.par.throughput = (data_size / (1024.0 * 1024.0)) /
                             (report.par.time_ms / 1000.0);

    report.speedup    = report.seq.time_ms / report.par.time_ms;
    report.threads    = threads;
    report.data_size  = data_size;

    free(cipher);
    free(plain);
    return report;
}

/* =========================================================
 * bench_print_report — In bảng kết quả đẹp
 * ========================================================= */
void bench_print_report(const BenchReport *reports, int count, const char *mode)
{
    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("  ║  Benchmark: AES-128 %s — %d Thread(s)\n", mode, reports[0].threads);
    printf("  ╠════════════╦═══════════════╦═══════════════╦══════════════╦════════╣\n");
    printf("  ║  Data Size ║  Sequential   ║  Parallel     ║  Throughput  ║Speedup ║\n");
    printf("  ║            ║  Time (ms)    ║  Time (ms)    ║ Par (MB/s)  ║        ║\n");
    printf("  ╠════════════╬═══════════════╬═══════════════╬══════════════╬════════╣\n");

    for (int i = 0; i < count; i++) {
        const BenchReport *r = &reports[i];
        double size_mb = r->data_size / (1024.0 * 1024.0);

        if (size_mb >= 1.0)
            printf("  ║  %6.0f MB  ║  %11.3f  ║  %11.3f  ║  %10.2f  ║ %5.2fx ║\n",
                   size_mb,
                   r->seq.time_ms, r->par.time_ms,
                   r->par.throughput, r->speedup);
        else
            printf("  ║  %6.0f KB  ║  %11.3f  ║  %11.3f  ║  %10.2f  ║ %5.2fx ║\n",
                   r->data_size / 1024.0,
                   r->seq.time_ms, r->par.time_ms,
                   r->par.throughput, r->speedup);
    }

    printf("  ╚════════════╩═══════════════╩═══════════════╩══════════════╩════════╝\n");
    printf("\n");
}
