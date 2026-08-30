"""Samples ~150 rows from real-1000.csv that do NOT overlap (by product_name+version)
with golden-300.csv, for the 2026-08-29 real-Claude-API cost measurement job. Throwaway
generator script, mirrors gen_golden_300.py / gen_400.py's style in this directory.
"""
import csv
import random

GOLDEN = "test-data/golden-300.csv"
REAL = "test-data/real-1000.csv"
OUT = "test-data/real-150-cost-test.csv"
SAMPLE_SIZE = 150
SEED = 20260829

with open(GOLDEN, newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    next(reader)  # header
    golden_keys = {(row[0].strip(), row[1].strip()) for row in reader if row}

with open(REAL, newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    real_header = next(reader)
    real_rows = [row for row in reader if row]

nondup_rows = [row for row in real_rows if (row[0].strip(), row[1].strip()) not in golden_keys]

print(f"golden keys: {len(golden_keys)}")
print(f"real-1000 rows: {len(real_rows)}")
print(f"non-overlapping rows: {len(nondup_rows)}")

random.seed(SEED)
sample = random.sample(nondup_rows, min(SAMPLE_SIZE, len(nondup_rows)))

with open(OUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(real_header)
    writer.writerows(sample)

print(f"wrote {len(sample)} sampled rows (+header) to {OUT}")
