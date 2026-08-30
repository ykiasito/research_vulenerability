#!/usr/bin/env python3
"""Policy-checklist verification for test-data/golden-300.csv: duplicate (product_name,
version) rows, holdout overlap against real-1000.csv, column-count hygiene, per-ecosystem /
per-outcome counts, ground_truth_source fill rate. Read-only, no network calls."""
import csv
from collections import Counter

with open("test-data/golden-300.csv", newline="") as f:
    reader = csv.DictReader(f)
    rows = list(reader)

print(f"Total rows: {len(rows)}")
print(f"Columns: {reader.fieldnames}")

# Column count hygiene
bad_cols = [r for r in rows if len(r) != len(reader.fieldnames)]
print(f"Rows with wrong column count: {len(bad_cols)}")

# ground_truth_source fill rate
blank_source = [r for r in rows if not r["ground_truth_source"].strip()]
print(f"Rows with blank ground_truth_source: {len(blank_source)}")

# Exact duplicate (product_name, version) within golden-300 itself
pairs = [(r["product_name"], r["version"]) for r in rows]
dupe_counts = Counter(pairs)
dupes = {k: v for k, v in dupe_counts.items() if v > 1}
print(f"Exact duplicate (product_name,version) pairs within golden-300.csv: {len(dupes)}")
if dupes:
    print(dupes)

# expected_outcome breakdown
outcome_counts = Counter(r["expected_outcome"] for r in rows)
print(f"expected_outcome breakdown: {dict(outcome_counts)}")

# ecosystem breakdown (registry rows only)
eco_counts = Counter(r["expected_ecosystem"] for r in rows if r["expected_outcome"] == "IDENTIFIED_REGISTRY")
print(f"IDENTIFIED_REGISTRY ecosystem breakdown: {dict(eco_counts)}")

# distinct product_name count
distinct_names = len(set(r["product_name"] for r in rows))
print(f"Distinct product_name count: {distinct_names}")

# Holdout overlap against real-1000.csv, on (product_name, version)
with open("test-data/real-1000.csv", newline="") as f:
    real1000_pairs = set((r["product_name"], r["version"]) for r in csv.DictReader(f))

overlap = [r for r in rows if (r["product_name"], r["version"]) in real1000_pairs]
holdout = [r for r in rows if (r["product_name"], r["version"]) not in real1000_pairs]
print(f"Rows overlapping real-1000.csv (product_name,version) exactly: {len(overlap)}")
print(f"Holdout rows (not in real-1000.csv): {len(holdout)}")
if overlap:
    print("Overlapping rows:")
    for r in overlap:
        print(f"  {r['product_name']} | {r['version']}")

# Which product_name is duplicated?
name_counts = Counter(r["product_name"] for r in rows)
dup_names = {k: v for k, v in name_counts.items() if v > 1}
print(f"Duplicate product_name values (any version): {dup_names}")

# Also check product_name-only overlap (weaker signal, informational)
real1000_names = set()
with open("test-data/real-1000.csv", newline="") as f:
    for r in csv.DictReader(f):
        real1000_names.add(r["product_name"])
name_overlap = [r for r in rows if r["product_name"] in real1000_names]
print(f"Rows whose product_name (any version) appears in real-1000.csv: {len(name_overlap)}")
