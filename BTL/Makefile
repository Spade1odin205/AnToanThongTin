# =========================================================
# Makefile — AES-128 Parallel với OpenMP
# =========================================================

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11 -Iinclude
OMPFLAG = -fopenmp
LDFLAGS = -lm

TARGET      = aes_demo
BENCH_CSV   = bench_csv

# Source files
SRCS    = main.c \
          src/aes_core.c \
          src/aes_sequential.c \
          src/aes_parallel.c \
          src/benchmark.c

CSV_SRCS = bench_csv.c \
           src/aes_core.c

OBJS    = $(SRCS:.c=.o)
CSV_OBJS = $(CSV_SRCS:.c=.o)

# ── Build rules ──────────────────────────────────────────

.PHONY: all clean run benchmark run-csv help

all: $(TARGET) $(BENCH_CSV)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OMPFLAG) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "  ✓ Build thành công! Chạy với: ./$(TARGET) [num_threads]"
	@echo ""

$(BENCH_CSV): $(CSV_OBJS)
	$(CC) $(CFLAGS) $(OMPFLAG) -o $@ $^ $(LDFLAGS)
	@echo "  ✓ bench_csv built"

%.o: %.c
	$(CC) $(CFLAGS) $(OMPFLAG) -c $< -o $@

# ── Run shortcuts ─────────────────────────────────────────

# Chạy với số thread mặc định (tự động phát hiện CPU cores)
run: $(TARGET)
	./$(TARGET)

# Chạy với 1 thread (baseline)
run-1t: $(TARGET)
	./$(TARGET) 1

# Chạy với 2 threads
run-2t: $(TARGET)
	./$(TARGET) 2

# Chạy với 4 threads
run-4t: $(TARGET)
	./$(TARGET) 4

# Chạy với 8 threads
run-8t: $(TARGET)
	./$(TARGET) 8

# Benchmark nhỏ gọn — xuất CSV, rồi vẽ biểu đồ
run-csv: $(BENCH_CSV)
	@echo "threads,mb,enc_seq,enc_par,enc_speedup,dec_seq,dec_par,dec_speedup,cbc_par,cbc_speedup" > results.csv
	./bench_csv 1 >> results.csv
	./bench_csv 2 >> results.csv
	./bench_csv 4 >> results.csv
	@echo "  ✓ Kết quả lưu vào results.csv"
	@python3 plot_speedup.py 2>/dev/null || echo "  (Cài matplotlib để xem biểu đồ: pip install matplotlib)"

# Benchmark đầy đủ (lâu hơn)
benchmark: $(TARGET)
	@echo "=== Benchmark: 1 Thread (baseline) ==="
	./$(TARGET) 1
	@echo "=== Benchmark: 2 Threads ==="
	./$(TARGET) 2
	@echo "=== Benchmark: 4 Threads ==="
	./$(TARGET) 4

# ── Clean ─────────────────────────────────────────────────

clean:
	rm -f $(TARGET) $(OBJS)
	@echo "  ✓ Đã xóa các file build"

# ── Help ──────────────────────────────────────────────────

help:
	@echo ""
	@echo "  AES-128 Parallel with OpenMP — Build Help"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make              — Build chương trình"
	@echo "  make run          — Chạy với số thread tự động"
	@echo "  make run-1t       — Chạy với 1 thread"
	@echo "  make run-4t       — Chạy với 4 threads"
	@echo "  make benchmark    — Benchmark 1/2/4/8 threads"
	@echo "  make clean        — Xóa file build"
	@echo "  ./aes_demo N      — Chạy với N threads tùy chọn"
	@echo ""
