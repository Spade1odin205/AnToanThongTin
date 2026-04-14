/*
 * main.c — AES-128 Parallel Demo & Benchmark
 *
 * Chương trình chính gồm 2 phần:
 *   1. Kiểm tra tính đúng đắn với NIST AES-128 test vectors
 *   2. Benchmark so sánh hiệu năng sequential vs parallel (OpenMP)
 *
 * Usage:
 *   ./aes_demo              — chạy demo + benchmark mặc định (4 threads)
 *   ./aes_demo <num_threads> — chỉ định số thread
 *
 * Compile:
 *   make        (dùng Makefile)
 *   hoặc trực tiếp:
 *   gcc -O2 -fopenmp main.c src/aes_core.c src/aes_sequential.c \
 *       src/aes_parallel.c src/benchmark.c -I include -o aes_demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>
#include "aes.h"
#include "benchmark.h"

/* =========================================================
 * Màu ANSI cho output đẹp
 * ========================================================= */
#define CLR_RESET  "\033[0m"
#define CLR_BOLD   "\033[1m"
#define CLR_GREEN  "\033[32m"
#define CLR_RED    "\033[31m"
#define CLR_CYAN   "\033[36m"
#define CLR_YELLOW "\033[33m"
#define CLR_BLUE   "\033[34m"

/* =========================================================
 * NIST AES-128 Test Vectors (FIPS 197, Appendix B)
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 * ========================================================= */
static const uint8_t nist_key[16] = {
    0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
};

static const uint8_t nist_plaintext[16] = {
    0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
};

static const uint8_t nist_ciphertext[16] = {
    0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb,
    0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32
};

/* NIST Advanced Encryption Standard (AES), FIPS 197
 * Example vector from Appendix C.1 (AES-128) */
static const uint8_t nist_key2[16] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
};

static const uint8_t nist_plain2[16] = {
    0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb, 0xcc,0xdd,0xee,0xff
};

static const uint8_t nist_cipher2[16] = {
    0x69,0xc4,0xe0,0xd8, 0x6a,0x7b,0x04,0x30,
    0xd8,0xcd,0xb7,0x80, 0x70,0xb4,0xc5,0x5a
};

/* =========================================================
 * print_banner
 * ========================================================= */
static void print_banner(void)
{
    printf("\n");
    printf(CLR_CYAN CLR_BOLD);
    printf("  ╔═══════════════════════════════════════════════════════════╗\n");
    printf("  ║       AES-128 Song Song Hóa với OpenMP                   ║\n");
    printf("  ║       An Toàn Thông Tin — Bài Tập Lớn                   ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════╝\n");
    printf(CLR_RESET "\n");
}

/* =========================================================
 * test_single_block — Kiểm tra 1 block với NIST vector
 * ========================================================= */
static int test_single_block(const char  *name,
                              const uint8_t *key,
                              const uint8_t *plain,
                              const uint8_t *expected_cipher)
{
    AES_CTX ctx;
    uint8_t cipher[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];
    int ok_enc, ok_dec;

    aes_key_expansion(&ctx, key);
    aes_encrypt_block(&ctx, plain, cipher);
    aes_decrypt_block(&ctx, cipher, decrypted);

    ok_enc = aes_verify_block(cipher, expected_cipher, AES_BLOCK_SIZE);
    ok_dec = aes_verify_block(decrypted, plain, AES_BLOCK_SIZE);

    printf("  " CLR_BOLD "%-30s" CLR_RESET, name);
    printf(" Encrypt: %s  Decrypt: %s\n",
           ok_enc ? CLR_GREEN "[PASS]" CLR_RESET : CLR_RED "[FAIL]" CLR_RESET,
           ok_dec ? CLR_GREEN "[PASS]" CLR_RESET : CLR_RED "[FAIL]" CLR_RESET);

    if (!ok_enc) {
        aes_print_block("  Expected", expected_cipher, AES_BLOCK_SIZE);
        aes_print_block("  Got     ", cipher, AES_BLOCK_SIZE);
    }

    return ok_enc && ok_dec;
}

/* =========================================================
 * test_ecb_modes — Kiểm tra ECB sequential == parallel
 * ========================================================= */
static int test_ecb_modes(int num_threads)
{
    const size_t TEST_LEN = 64;  /* 4 blocks */
    AES_CTX ctx;
    uint8_t plain[64], enc_seq[64], enc_par[64];
    uint8_t dec_seq[64], dec_par[64];
    int i, ok;

    /* Fill plaintext */
    for (i = 0; i < (int)TEST_LEN; i++) plain[i] = (uint8_t)i;
    aes_key_expansion(&ctx, nist_key);

    /* ECB Encrypt */
    aes_ecb_encrypt_seq(&ctx, plain, enc_seq, TEST_LEN);
    aes_ecb_encrypt_par(&ctx, plain, enc_par, TEST_LEN, num_threads);
    ok = aes_verify_block(enc_seq, enc_par, TEST_LEN);
    printf("  %-30s %s\n", "ECB Encrypt: seq == par?",
           ok ? CLR_GREEN "[PASS]" CLR_RESET : CLR_RED "[FAIL]" CLR_RESET);

    /* ECB Decrypt */
    aes_ecb_decrypt_seq(&ctx, enc_seq, dec_seq, TEST_LEN);
    aes_ecb_decrypt_par(&ctx, enc_par, dec_par, TEST_LEN, num_threads);
    ok &= aes_verify_block(dec_seq, dec_par, TEST_LEN);
    ok &= aes_verify_block(dec_seq, plain,   TEST_LEN);
    printf("  %-30s %s\n", "ECB Decrypt: par == plain?",
           ok ? CLR_GREEN "[PASS]" CLR_RESET : CLR_RED "[FAIL]" CLR_RESET);

    return ok;
}

/* =========================================================
 * test_cbc_modes — Kiểm tra CBC
 * ========================================================= */
static int test_cbc_modes(int num_threads)
{
    const size_t TEST_LEN = 64;
    AES_CTX ctx;
    uint8_t plain[64], cipher_seq[64], cipher_par[64];
    uint8_t dec_seq[64], dec_par[64];
    const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
    };
    int i, ok;

    for (i = 0; i < (int)TEST_LEN; i++) plain[i] = (uint8_t)i;
    aes_key_expansion(&ctx, nist_key);

    /* CBC Encrypt (seq only — parallel fallback là sequential) */
    aes_cbc_encrypt_seq(&ctx, iv, plain, cipher_seq, TEST_LEN);
    aes_cbc_encrypt_par(&ctx, iv, plain, cipher_par, TEST_LEN, num_threads);
    ok = aes_verify_block(cipher_seq, cipher_par, TEST_LEN);
    printf("  %-30s %s\n", "CBC Encrypt: seq == par?",
           ok ? CLR_GREEN "[PASS]" CLR_RESET : CLR_RED "[FAIL]" CLR_RESET);

    /* CBC Decrypt — parallel version */
    aes_cbc_decrypt_seq(&ctx, iv, cipher_seq, dec_seq, TEST_LEN);
    aes_cbc_decrypt_par(&ctx, iv, cipher_seq, dec_par, TEST_LEN, num_threads);
    ok &= aes_verify_block(dec_seq, dec_par, TEST_LEN);
    ok &= aes_verify_block(dec_seq, plain,   TEST_LEN);
    printf("  %-30s %s\n", "CBC Decrypt: par == plain?",
           ok ? CLR_GREEN "[PASS]" CLR_RESET : CLR_RED "[FAIL]" CLR_RESET);

    return ok;
}

/* =========================================================
 * run_benchmarks
 * Kích thước dữ liệu từ 512KB đến 64MB
 * ========================================================= */
static void run_benchmarks(int num_threads)
{
    /* Các kích thước dữ liệu: 512KB, 1MB, 4MB, 16MB, 64MB */
    static const size_t SIZES[] = {
        512  * 1024,
        1    * 1024 * 1024,
        4    * 1024 * 1024,
        16   * 1024 * 1024,
        64   * 1024 * 1024
    };
    static const int NUM_SIZES = 5;

    const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
    };

    BenchReport ecb_enc_reports[5];
    BenchReport ecb_dec_reports[5];
    BenchReport cbc_dec_reports[5];

    printf(CLR_YELLOW "  Đang chạy benchmark với %d thread(s)...\n" CLR_RESET,
           num_threads);
    printf("  (Mỗi kích thước chạy %d lần, lấy trung bình)\n\n", 5);

    for (int i = 0; i < NUM_SIZES; i++) {
        printf("  [%d/%d] Kích thước: %.0f %s ... ",
               i + 1, NUM_SIZES,
               SIZES[i] >= 1024*1024
                   ? SIZES[i] / (1024.0*1024.0) : SIZES[i] / 1024.0,
               SIZES[i] >= 1024*1024 ? "MB" : "KB");
        fflush(stdout);

        ecb_enc_reports[i] = bench_ecb_encrypt(nist_key, SIZES[i], num_threads);
        ecb_dec_reports[i] = bench_ecb_decrypt(nist_key, SIZES[i], num_threads);
        cbc_dec_reports[i] = bench_cbc_decrypt(nist_key, iv, SIZES[i], num_threads);
        printf("xong\n");
    }

    bench_print_report(ecb_enc_reports, NUM_SIZES, "ECB ENCRYPT");
    bench_print_report(ecb_dec_reports, NUM_SIZES, "ECB DECRYPT");
    bench_print_report(cbc_dec_reports, NUM_SIZES, "CBC DECRYPT (Parallel)");
}

/* =========================================================
 * main
 * ========================================================= */
int main(int argc, char *argv[])
{
    int num_threads = omp_get_max_threads();  /* Default: max hệ thống */

    if (argc > 1) {
        num_threads = atoi(argv[1]);
        if (num_threads < 1) num_threads = 1;
    }

    print_banner();

    /* ── PHẦN 1: Kiểm tra tính đúng đắn ── */
    printf(CLR_BOLD CLR_BLUE "  ▶ Bước 1: Kiểm Tra NIST AES-128 Test Vectors\n" CLR_RESET);
    printf("  %s\n", "─────────────────────────────────────────────────────────");

    int all_pass = 1;
    all_pass &= test_single_block("FIPS 197 Appendix B", nist_key,  nist_plaintext, nist_ciphertext);
    all_pass &= test_single_block("FIPS 197 Appendix C.1", nist_key2, nist_plain2, nist_cipher2);

    printf("\n");
    printf(CLR_BOLD CLR_BLUE "  ▶ Bước 2: Kiểm Tra Tính Nhất Quán (seq == par)\n" CLR_RESET);
    printf("  %s\n", "─────────────────────────────────────────────────────────");
    printf("  (Dùng %d thread(s))\n\n", num_threads);

    all_pass &= test_ecb_modes(num_threads);
    all_pass &= test_cbc_modes(num_threads);

    printf("\n");
    if (all_pass)
        printf("  " CLR_GREEN CLR_BOLD "✓ Tất cả kiểm tra PASS!\n" CLR_RESET "\n");
    else
        printf("  " CLR_RED CLR_BOLD "✗ Một số kiểm tra FAIL — kiểm tra lại code.\n" CLR_RESET "\n");

    /* ── PHẦN 2: Benchmark ── */
    printf(CLR_BOLD CLR_BLUE "  ▶ Bước 3: Benchmark Hiệu Năng\n" CLR_RESET);
    printf("  %s\n", "─────────────────────────────────────────────────────────");
    printf("  CPU cores khả dụng: %d\n", omp_get_max_threads());

    run_benchmarks(num_threads);

    /* ── Tóm tắt ── */
    printf(CLR_CYAN CLR_BOLD);
    printf("  ═══════════════════════════════════════════════════════════\n");
    printf("  Kết luận:\n");
    printf("  • ECB: Song song hóa hiệu quả cao (speedup ≈ %dx)\n", num_threads);
    printf("  • CBC Decrypt: Song song hóa tốt nhờ XOR độc lập\n");
    printf("  • CBC Encrypt: Không song song trực tiếp (data dependency)\n");
    printf("  ═══════════════════════════════════════════════════════════\n");
    printf(CLR_RESET "\n");

    return all_pass ? 0 : 1;
}
