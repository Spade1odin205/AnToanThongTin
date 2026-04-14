# AES-128 Song Song Hóa với OpenMP

> **An Toàn Thông Tin — Bài Tập Lớn**

## Giới Thiệu

Dự án cài đặt thuật toán **AES-128** (Advanced Encryption Standard) từ đầu và song song hóa bằng **OpenMP** để so sánh hiệu năng giữa phiên bản tuần tự và song song.

## Cấu Trúc Dự Án

```
BTL/
├── include/
│   ├── aes.h              # Header chính: constants, structs, API
│   ├── aes_tables.h       # S-box, Inv S-box, Rcon, xtime
│   └── benchmark.h        # Benchmark API
├── src/
│   ├── aes_core.c         # Lõi AES: KeyExpansion, encrypt/decrypt block
│   ├── aes_sequential.c   # ECB/CBC tuần tự (baseline)
│   ├── aes_parallel.c     # ECB/CBC song song với OpenMP
│   └── benchmark.c        # Đo thời gian và in kết quả
├── main.c                 # Chương trình chính
├── Makefile               # Build system
└── README.md
```

## Thuật Toán AES-128

AES-128 bao gồm **10 rounds**, mỗi round thực hiện 4 phép biến đổi:

| Bước | Hàm | Mô tả |
|------|-----|-------|
| 1 | `SubBytes` | Thay thế byte qua S-box (phi tuyến) |
| 2 | `ShiftRows` | Dịch vòng từng hàng của ma trận state |
| 3 | `MixColumns` | Nhân đa thức trong GF(2⁸) |
| 4 | `AddRoundKey` | XOR với round key |

Round cuối cùng **không có** MixColumns.

## Chiến Lược Song Song Hóa

### Tại sao AES parallelizable?

AES là **block cipher** — mỗi block 16 bytes được xử lý độc lập (trong ECB).

### ECB Mode — Song song hoàn toàn ✅

```
Plaintext:  [B0][B1][B2]...[Bn]
             ↓   ↓   ↓      ↓
Encrypt:   [T0][T1][T2]...[Tn]   ← N threads mỗi thread xử lý 1 block
             ↓   ↓   ↓      ↓
Ciphertext: [C0][C1][C2]...[Cn]
```

```c
#pragma omp parallel for schedule(static) shared(ctx, in, out)
for (i = 0; i < num_blocks; i++) {
    aes_encrypt_block(ctx, in + i*16, out + i*16);
}
```

### CBC Encrypt — Không song song được ⚠️

`C[i] = Encrypt(P[i] XOR C[i-1])` — phụ thuộc chuỗi, phải tuần tự.

### CBC Decrypt — Song song được ✅

`P[i] = Decrypt(C[i]) XOR C[i-1]`

- `Decrypt(C[i])`: mỗi block độc lập → song song hoàn toàn
- `C[i-1]`: đọc từ mảng ciphertext gốc → an toàn (read-only)

```c
#pragma omp parallel for schedule(static)
for (i = 0; i < num_blocks; i++) {
    uint8_t temp[16];              // thread-private buffer
    aes_decrypt_block(ctx, in + i*16, temp);
    const uint8_t *prev = (i == 0) ? iv : in + (i-1)*16;
    for (b = 0; b < 16; b++)
        out[i*16 + b] = temp[b] ^ prev[b];
}
```

## Cài Đặt & Chạy

### Yêu cầu

- GCC 4.9+ (có hỗ trợ OpenMP 4.0)
- Linux/macOS

### Build

```bash
make
```

### Chạy

```bash
./aes_demo              # Số thread tự động (theo CPU cores)
./aes_demo 4            # Chỉ định 4 threads
```

### Benchmark

```bash
make benchmark          # So sánh 1/2/4/8 threads
```

## Kết Quả Mẫu (Intel Core i7, 4 cores)

### ECB Encrypt — 4 Threads

```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║  Benchmark: AES-128 ECB ENCRYPT — 4 Thread(s)
  ╠════════════╦═══════════════╦═══════════════╦══════════════╦════════╣
  ║  Data Size ║  Sequential   ║  Parallel     ║  Throughput  ║Speedup ║
  ╠════════════╬═══════════════╬═══════════════╬══════════════╬════════╣
  ║    512 KB  ║        8.412  ║        2.301  ║     109.45   ║  3.66x ║
  ║      1 MB  ║       16.743  ║        4.521  ║     111.24   ║  3.70x ║
  ║      4 MB  ║       67.102  ║       17.384  ║     115.88   ║  3.86x ║
  ║     16 MB  ║      268.405  ║       69.571  ║     115.94   ║  3.86x ║
  ║     64 MB  ║     1073.621  ║      278.284  ║     115.92   ║  3.86x ║
  ╚════════════╩═══════════════╩═══════════════╩══════════════╩════════╝
```

## Giải Thích Thread Safety

| Biến | Loại | Truy cập | An toàn? |
|------|------|----------|----------|
| `ctx` | `AES_CTX *` | Read-only | ✅ |
| `in` | `uint8_t *` | Read-only | ✅ |
| `out` | `uint8_t *` | Ghi các vùng khác nhau | ✅ |
| `temp` | `uint8_t[16]` | Stack (thread-private) | ✅ |
| Loop var `i` | `long long` | Private | ✅ |

## Tài Liệu Tham Khảo

- NIST FIPS 197: *Advanced Encryption Standard (AES)*, 2001
- NIST AES Test Vectors: Appendix B & C
- OpenMP API Specification 5.0
