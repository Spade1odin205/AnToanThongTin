/*
 * aes_parallel.c — Parallel AES Modes using OpenMP
 *
 * Song song hóa (parallelization) strategy:
 *
 *  ECB Encrypt/Decrypt:
 *    - Mỗi block 16 bytes HOÀN TOÀN ĐỘC LẬP → parallel for lý tưởng.
 *    - Dùng #pragma omp parallel for với schedule(static) để phân chia
 *      đều các block cho các thread.
 *
 *  CBC Encrypt:
 *    - Block i phụ thuộc vào ciphertext block i-1 → KHÔNG thể song song.
 *    - Ta vẫn dùng sequential cho encrypt nhưng chia dữ liệu theo chunk
 *      cho pipeline parallelism khi tích hợp với I/O.
 *    - Ở đây cài đặt sequential (giống baseline) để đảm bảo đúng đắn.
 *
 *  CBC Decrypt:
 *    - Decrypt(C[i]) không phụ thuộc block khác → song song được.
 *    - XOR với C[i-1] thực hiện NGAY SAU khi decrypt, vẫn song song:
 *        P[i] = Decrypt(C[i]) XOR C[i-1]
 *    - Truy cập C[i-1] và C[i] là read-only từ mảng ciphertext gốc.
 *
 * Compile: gcc -fopenmp ...
 */

#include <string.h>
#include <omp.h>
#include "aes.h"

/* =========================================================
 * ECB Encrypt — Parallel
 *
 * Tất cả num_blocks block được phân phối cho các OpenMP threads.
 * schedule(static): phân chia đều, phù hợp khi mỗi block tốn
 *   thời gian như nhau (workload đồng đều).
 * ========================================================= */
void aes_ecb_encrypt_par(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads)
{
    size_t num_blocks = len / AES_BLOCK_SIZE;
    long long i;      /* OpenMP yêu cầu kiểu có dấu cho loop variable */

    omp_set_num_threads(num_threads);

    #pragma omp parallel for schedule(static) \
        shared(ctx, in, out) \
        firstprivate(num_blocks) \
        default(none)
    for (i = 0; i < (long long)num_blocks; i++) {
        aes_encrypt_block(ctx,
                          in  + i * AES_BLOCK_SIZE,
                          out + i * AES_BLOCK_SIZE);
    }
}

/* =========================================================
 * ECB Decrypt — Parallel
 * ========================================================= */
void aes_ecb_decrypt_par(const AES_CTX *ctx,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads)
{
    size_t num_blocks = len / AES_BLOCK_SIZE;
    long long i;

    omp_set_num_threads(num_threads);

    #pragma omp parallel for schedule(static) \
        shared(ctx, in, out) \
        firstprivate(num_blocks) \
        default(none)
    for (i = 0; i < (long long)num_blocks; i++) {
        aes_decrypt_block(ctx,
                          in  + i * AES_BLOCK_SIZE,
                          out + i * AES_BLOCK_SIZE);
    }
}

/* =========================================================
 * CBC Encrypt — Parallel (với kỹ thuật Independent Chain)
 *
 * Phân tích:
 *   C[0] = Enc(P[0] ^ IV)
 *   C[1] = Enc(P[1] ^ C[0])   ← phụ thuộc C[0]
 *   C[i] = Enc(P[i] ^ C[i-1]) ← phụ thuộc C[i-1]
 *
 * → Không thể song song hóa trực tiếp.
 *
 * Kỹ thuật nâng cao (Independent Chain Parallel CBC):
 *   - Chia dữ liệu thành T chunk (T = số thread).
 *   - Mỗi thread encrypt độc lập chunk của mình với IV riêng.
 *   - Sau đó "stitch" lại: propagate IV thực từ cuối chunk trước
 *     sang đầu chunk sau và re-encrypt.
 *
 * Ở đây ta cài đặt phiên bản đơn giản (sequential fallback) vì
 * CBC Encrypt không parallelizable một cách tầm thường.
 * CBC Decrypt là hàm được song song hóa chính.
 * ========================================================= */
void aes_cbc_encrypt_par(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads)
{
    /*
     * CBC Encrypt: sequential by nature.
     * Lưu ý: num_threads được nhận nhưng không dùng vì
     * thuật toán bị ràng buộc data dependency.
     * (Xem aes_cbc_decrypt_par để thấy ví dụ song song thực sự.)
     */
    (void)num_threads;

    size_t i, b;
    size_t num_blocks = len / AES_BLOCK_SIZE;
    uint8_t xored[AES_BLOCK_SIZE];
    const uint8_t *prev = iv;

    for (i = 0; i < num_blocks; i++) {
        for (b = 0; b < AES_BLOCK_SIZE; b++)
            xored[b] = in[i * AES_BLOCK_SIZE + b] ^ prev[b];
        aes_encrypt_block(ctx, xored, out + i * AES_BLOCK_SIZE);
        prev = out + i * AES_BLOCK_SIZE;
    }
}

/* =========================================================
 * CBC Decrypt — Parallel ✅
 *
 * Phân tích:
 *   P[i] = Decrypt(C[i]) XOR C[i-1]   (C[-1] = IV)
 *
 * Decrypt(C[i]) : KHÔNG phụ thuộc block khác → song song được!
 * XOR với C[i-1]: C[i-1] là ciphertext gốc (read-only) → an toàn khi đọc.
 *
 * → Tất cả block có thể decrypt song song hoàn toàn.
 *
 * Thread safety:
 *   - ctx   : read-only, an toàn cho mọi thread.
 *   - in    : read-only (ciphertext), an toàn.
 *   - out   : mỗi thread ghi vào vùng khác nhau (i*16 đến i*16+15).
 *   - iv    : chỉ đọc 1 lần cho block đầu (i==0), an toàn.
 * ========================================================= */
void aes_cbc_decrypt_par(const AES_CTX *ctx,
                          const uint8_t *iv,
                          const uint8_t *in, uint8_t *out,
                          size_t len, int num_threads)
{
    size_t num_blocks = len / AES_BLOCK_SIZE;
    long long i;

    omp_set_num_threads(num_threads);

    /*
     * Mỗi thread xử lý một tập block độc lập:
     *   1. Decrypt ciphertext block → temp (local stack, thread-private)
     *   2. XOR với ciphertext block trước (hoặc IV) → plaintext
     *
     * Biến temp là stack-allocated trong mỗi iteration → thread-private
     * tự động (không cần khai báo private vì mỗi thread có stack riêng).
     */
    #pragma omp parallel for schedule(static) \
        shared(ctx, in, out, iv) \
        firstprivate(num_blocks) \
        default(none)
    for (i = 0; i < (long long)num_blocks; i++) {
        uint8_t temp[AES_BLOCK_SIZE];  /* thread-private buffer */
        size_t  b;

        /* Step 1: Decrypt ciphertext block i */
        aes_decrypt_block(ctx, in + i * AES_BLOCK_SIZE, temp);

        /* Step 2: XOR with previous ciphertext (or IV for i==0) */
        const uint8_t *prev = (i == 0) ? iv : in + (i - 1) * AES_BLOCK_SIZE;
        for (b = 0; b < AES_BLOCK_SIZE; b++)
            out[i * AES_BLOCK_SIZE + b] = temp[b] ^ prev[b];
    }
}
