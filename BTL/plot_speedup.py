#!/usr/bin/env python3
"""
plot_speedup.py — Vẽ biểu đồ speedup AES-128 Parallel vs Sequential
Đọc từ results.csv và xuất file ảnh PNG.

Usage:
    python3 plot_speedup.py            # Đọc results.csv mặc định
    python3 plot_speedup.py myfile.csv # Đọc file tùy chọn
"""

import sys
import csv
import os
from collections import defaultdict

# ── Kiểm tra matplotlib ──────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend (không cần display)
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("⚠ matplotlib không có sẵn. Cài đặt: pip install matplotlib")
    print("  Hiển thị kết quả dạng bảng text thay thế.\n")

# ── Đọc dữ liệu CSV ──────────────────────────────────────
csv_file = sys.argv[1] if len(sys.argv) > 1 else "results.csv"

if not os.path.exists(csv_file):
    print(f"❌ Không tìm thấy file: {csv_file}")
    print("   Chạy 'make run-csv' để tạo dữ liệu benchmark.")
    sys.exit(1)

# data[threads][mb] = {enc_speedup, dec_speedup, cbc_speedup}
data = defaultdict(dict)
all_threads = set()
all_sizes   = []

with open(csv_file, newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        t  = int(row['threads'])
        mb = float(row['mb'])
        all_threads.add(t)
        if mb not in all_sizes:
            all_sizes.append(mb)
        data[t][mb] = {
            'enc_seq':      float(row['enc_seq']),
            'enc_par':      float(row['enc_par']),
            'enc_speedup':  float(row['enc_speedup']),
            'dec_seq':      float(row['dec_seq']),
            'dec_par':      float(row['dec_par']),
            'dec_speedup':  float(row['dec_speedup']),
            'cbc_par':      float(row['cbc_par']),
            'cbc_speedup':  float(row['cbc_speedup']),
        }

all_threads = sorted(all_threads)
all_sizes   = sorted(all_sizes)

# ── In bảng text ─────────────────────────────────────────
print("=" * 72)
print("  AES-128 Benchmark Results (Sequential vs Parallel)")
print("=" * 72)

for mode, key in [("ECB Encrypt", "enc_speedup"),
                   ("ECB Decrypt", "dec_speedup"),
                   ("CBC Decrypt", "cbc_speedup")]:
    print(f"\n  ── {mode} Speedup ──")
    header = f"  {'MB':>6}" + "".join(f"  {t}T speedup" for t in all_threads)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for mb in all_sizes:
        row_str = f"  {mb:>6.1f}"
        for t in all_threads:
            if mb in data[t]:
                row_str += f"     {data[t][mb][key]:5.2f}x  "
            else:
                row_str += f"       N/A  "
        print(row_str)

print()

# ── Vẽ biểu đồ ───────────────────────────────────────────
if not HAS_MPL:
    sys.exit(0)

# Màu sắc theo chủ đề đẹp
COLORS = {
    1: '#94a3b8',   # slate (baseline)
    2: '#60a5fa',   # blue
    4: '#34d399',   # emerald
    8: '#f472b6',   # pink
}
MARKERS = {1: 'o', 2: 's', 4: '^', 8: 'D'}

fig, axes = plt.subplots(1, 3, figsize=(15, 5))
fig.patch.set_facecolor('#0f172a')

MODES = [
    ("ECB Encrypt Speedup", "enc_speedup"),
    ("ECB Decrypt Speedup", "dec_speedup"),
    ("CBC Decrypt Speedup", "cbc_speedup"),
]

for ax, (title, key) in zip(axes, MODES):
    ax.set_facecolor('#1e293b')
    ax.tick_params(colors='#cbd5e1', labelsize=9)
    ax.spines[:].set_color('#334155')
    ax.yaxis.grid(True, color='#334155', linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)

    for t in all_threads:
        if t == 1:
            continue  # Baseline speedup = 1x, bỏ qua
        xs = []
        ys = []
        for mb in all_sizes:
            if mb in data[t]:
                xs.append(mb)
                ys.append(data[t][mb][key])

        color  = COLORS.get(t, '#fff')
        marker = MARKERS.get(t, 'o')

        ax.plot(xs, ys,
                color=color, marker=marker,
                linewidth=2, markersize=7,
                label=f'{t} Threads')

        # Annotate last point
        if xs:
            ax.annotate(f'{ys[-1]:.2f}x',
                        xy=(xs[-1], ys[-1]),
                        xytext=(5, 3), textcoords='offset points',
                        color=color, fontsize=8, fontweight='bold')

    # Linear speedup reference
    max_t_shown = max(t for t in all_threads if t > 1)
    ax.axhline(y=max_t_shown, color='#475569', linestyle=':', linewidth=1.2,
               label=f'Lý tưởng ({max_t_shown}x)')

    ax.set_title(title, color='#f1f5f9', fontsize=12, fontweight='bold', pad=10)
    ax.set_xlabel('Kích thước dữ liệu (MB)', color='#94a3b8', fontsize=9)
    ax.set_ylabel('Speedup (lần)', color='#94a3b8', fontsize=9)
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f'{x:.0f}' if x >= 1 else f'{x*1024:.0f}K'))
    ax.legend(facecolor='#1e293b', edgecolor='#334155',
              labelcolor='#cbd5e1', fontsize=8)
    ax.set_ylim(bottom=0)

fig.suptitle('AES-128 Song Song Hóa với OpenMP — Speedup Analysis',
             color='#f1f5f9', fontsize=14, fontweight='bold', y=1.02)

plt.tight_layout()
out_file = 'speedup_chart.png'
plt.savefig(out_file, dpi=150, bbox_inches='tight',
            facecolor=fig.get_facecolor())
print(f"✓ Biểu đồ đã lưu vào: {out_file}")

# ── Vẽ biểu đồ Throughput riêng ──────────────────────────
fig2, axes2 = plt.subplots(1, 2, figsize=(12, 5))
fig2.patch.set_facecolor('#0f172a')

THRU_MODES = [
    ("ECB Encrypt Throughput (MB/s)", "enc_seq", "enc_par"),
    ("ECB Decrypt Throughput (MB/s)", "dec_seq", "dec_par"),
]

for ax, (title, seq_key, par_key) in zip(axes2, THRU_MODES):
    ax.set_facecolor('#1e293b')
    ax.tick_params(colors='#cbd5e1', labelsize=9)
    ax.spines[:].set_color('#334155')
    ax.yaxis.grid(True, color='#334155', linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)

    # Sequential baseline
    xs = all_sizes
    seq_thru = []
    for mb in xs:
        t1 = all_threads[0]
        if mb in data[t1]:
            ms = data[t1][mb][seq_key]
            seq_thru.append((mb / ms) * 1000)  # MB/s
        else:
            seq_thru.append(0)

    ax.plot(xs, seq_thru, color='#94a3b8', marker='o',
            linewidth=2, markersize=6, linestyle='--', label='Sequential')

    for t in all_threads:
        if t == all_threads[0]:
            continue
        ys = []
        for mb in xs:
            if mb in data[t]:
                ms = data[t][mb][par_key]
                ys.append((mb / ms) * 1000)
            else:
                ys.append(0)
        color  = COLORS.get(t, '#fff')
        marker = MARKERS.get(t, 'o')
        ax.plot(xs, ys, color=color, marker=marker,
                linewidth=2, markersize=6, label=f'{t} Threads')

    ax.set_title(title, color='#f1f5f9', fontsize=12, fontweight='bold', pad=10)
    ax.set_xlabel('Kích thước dữ liệu (MB)', color='#94a3b8', fontsize=9)
    ax.set_ylabel('Throughput (MB/s)', color='#94a3b8', fontsize=9)
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f'{x:.0f}' if x >= 1 else f'{x*1024:.0f}K'))
    ax.legend(facecolor='#1e293b', edgecolor='#334155',
              labelcolor='#cbd5e1', fontsize=8)
    ax.set_ylim(bottom=0)

fig2.suptitle('AES-128 Throughput Comparison (MB/s)',
              color='#f1f5f9', fontsize=14, fontweight='bold', y=1.02)

plt.tight_layout()
out_file2 = 'throughput_chart.png'
plt.savefig(out_file2, dpi=150, bbox_inches='tight',
            facecolor=fig2.get_facecolor())
print(f"✓ Biểu đồ throughput lưu vào: {out_file2}")
