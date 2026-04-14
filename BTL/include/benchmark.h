#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stddef.h>
#include <stdint.h>

/* =========================================================
 * Benchmark Structures
 * ========================================================= */
typedef struct {
    double time_ms;     /* elapsed time in milliseconds  */
    double throughput;  /* MB/s                          */
} BenchResult;

typedef struct {
    BenchResult seq;    /* sequential result             */
    BenchResult par;    /* parallel result               */
    double      speedup;
    int         threads;
    size_t      data_size;
} BenchReport;

/* =========================================================
 * Benchmark API
 * ========================================================= */

/* Returns wall-clock time in milliseconds */
double bench_now_ms(void);

/* Runs ECB encrypt benchmark, sequential vs parallel */
BenchReport bench_ecb_encrypt(const uint8_t *key, size_t data_size, int threads);

/* Runs ECB decrypt benchmark, sequential vs parallel */
BenchReport bench_ecb_decrypt(const uint8_t *key, size_t data_size, int threads);

/* Runs CBC decrypt benchmark, sequential vs parallel */
BenchReport bench_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                               size_t data_size, int threads);

/* Print a pretty benchmark table */
void bench_print_report(const BenchReport *reports, int count, const char *mode);

#endif /* BENCHMARK_H */
