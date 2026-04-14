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

## Kết Quả Benchmark Thực Tế (4 CPU Cores)

> Môi trường: Linux, GCC với `-O2 -fopenmp`, đo trung bình 3 lần chạy.

### ECB Encrypt Speedup

| Kích thước | Sequential (ms) | 2 Threads (ms) | Speedup 2T | 4 Threads (ms) | Speedup 4T |
|-----------|----------------|---------------|------------|---------------|------------|
| 0.5 MB    | 11.757         | 8.068         | 1.48x      | 7.170         | 1.43x      |
| 1 MB      | 21.258         | 16.993        | 1.37x      | 8.481         | **2.44x**  |
| 2 MB      | 41.611         | 20.744        | 2.15x      | 10.647        | **3.88x**  |
| 4 MB      | 84.223         | 43.027        | 1.98x      | 21.380        | **3.84x**  |
| 8 MB      | 165.929        | 83.059        | 2.00x      | 42.234        | **4.06x**  |
| 16 MB     | 325.269        | 162.084       | 2.05x      | 86.700        | **3.86x**  |

### ECB Decrypt Speedup

| Kích thước | Sequential (ms) | 2 Threads (ms) | Speedup 2T | 4 Threads (ms) | Speedup 4T |
|-----------|----------------|---------------|------------|---------------|------------|
| 0.5 MB    | 135.340        | 71.633        | 2.03x      | 34.928        | **3.87x**  |
| 1 MB      | 271.905        | 139.056       | 2.03x      | 76.110        | **3.56x**  |
| 2 MB      | 546.364        | 284.939       | 1.96x      | 138.754       | **3.94x**  |
| 4 MB      | 1084.450       | 541.662       | 2.00x      | 276.386       | **3.91x**  |
| 8 MB      | 2185.592       | 1095.580      | 1.99x      | 570.488       | **3.83x**  |
| 16 MB     | 4349.400       | 2184.251      | 1.99x      | 1122.757      | **3.87x**  |

### CBC Decrypt Speedup (song song hóa hoàn toàn)

| Kích thước | Sequential (ms) | 2 Threads (ms) | Speedup 2T | 4 Threads (ms) | Speedup 4T |
|-----------|----------------|---------------|------------|---------------|------------|
| 0.5 MB    | 137.891        | 80.044        | 1.78x      | 35.114        | **3.88x**  |
| 1 MB      | 268.116        | 136.891       | 2.02x      | 68.349        | **4.04x**  |
| 2 MB      | 548.813        | 292.982       | 1.88x      | 138.097       | **3.89x**  |
| 4 MB      | 1099.159       | 537.827       | 2.04x      | 277.517       | **4.02x**  |
| 8 MB      | 2157.894       | 1115.326      | 1.94x      | 553.502       | **3.93x**  |
| 16 MB     | 4386.906       | 2162.898      | 2.02x      | 1132.121      | **3.82x**  |

### Nhận Xét

- **ECB & CBC Decrypt với 4 threads**: Speedup trung bình **~3.8–4.0x** — gần đạt linear scaling lý tưởng (4x).
- **CBC Encrypt**: Không thể song song hóa do data dependency giữa các block (speedup ≈ 1x).
- Overhead thread creation là rõ rệt ở kích thước nhỏ (0.5 MB), giảm dần khi tăng kích thước.
- Kết quả tốt nhất đạt **4.06x** với 4 threads trên 8 MB (ECB Encrypt).

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
