#!/usr/bin/env python3
"""Stratified sampling of golden-300.csv down to ~250 rows for the first AI-included accuracy
run against golden-300 (2026-08-29). Job 168 (the only prior run of this dataset) was static-only
(no Claude key configured), so this is the first time AI is actually exercised against it. Real
Claude balance is $1.29, and a full 300-item run risks the $0.005/item*300=$1.50 budget cap
exceeding that balance, so this trims to ~250 items (budget cap $1.25) while preserving the
dataset's per-expected_outcome ratio (IDENTIFIED_REGISTRY / IDENTIFIED_CPE / UNIDENTIFIED), so the
250-item run stays a fair (if smaller) proxy for the full 300-item accuracy picture rather than
skewing toward one outcome bucket.

Sampling is stratified by expected_outcome: each bucket is downsampled by the same ~250/300
ratio (rounded), using a fixed seed for reproducibility. Output keeps the original golden-300.csv
column order/header and the original row order (not sample order) so it stays diffable/readable
against the source file.
"""
import csv
import random

SEED = 20260829
TARGET_TOTAL = 250
SRC = "test-data/golden-300.csv"
DST = "test-data/golden-250-ai-test.csv"

with open(SRC, newline="") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    rows = list(reader)

print(f"source rows: {len(rows)}")

by_outcome = {}
for r in rows:
    by_outcome.setdefault(r["expected_outcome"], []).append(r)

print("source distribution:")
for k, v in sorted(by_outcome.items()):
    print(f"  {k}: {len(v)}")

ratio = TARGET_TOTAL / len(rows)
rng = random.Random(SEED)

# Largest-remainder method: round each bucket's share down, then hand out the leftover slots
# (target - sum of floors) one at a time to the buckets with the largest fractional remainder,
# so the total lands exactly on TARGET_TOTAL instead of drifting by rounding error (167+57+27=251
# with plain round()) while keeping each bucket's share as close to the overall ratio as possible.
outcomes_sorted = sorted(by_outcome.keys())
raw_shares = {o: len(by_outcome[o]) * ratio for o in outcomes_sorted}
counts = {o: int(raw_shares[o]) for o in outcomes_sorted}  # floor
remainder_slots = TARGET_TOTAL - sum(counts.values())
by_remainder = sorted(outcomes_sorted, key=lambda o: raw_shares[o] - counts[o], reverse=True)
for o in by_remainder[:remainder_slots]:
    counts[o] += 1

selected = []
for outcome, bucket in by_outcome.items():
    n = min(counts[outcome], len(bucket))
    chosen = rng.sample(bucket, n)
    selected.extend(chosen)

print(f"\nselected total: {len(selected)} (target was {TARGET_TOTAL})")
print("selected distribution:")
selected_by_outcome = {}
for r in selected:
    selected_by_outcome.setdefault(r["expected_outcome"], []).append(r)
for k, v in sorted(selected_by_outcome.items()):
    orig = len(by_outcome[k])
    print(f"  {k}: {len(v)}/{orig} kept ({len(v)/orig:.4f} vs overall ratio {ratio:.4f})")

# Preserve original golden-300.csv row order in the output (not the per-bucket sample order),
# so the file stays easy to diff/eyeball against the source.
selected_keys = {(r["product_name"], r["version"]) for r in selected}
ordered_selected = [r for r in rows if (r["product_name"], r["version"]) in selected_keys]

with open(DST, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(ordered_selected)

print(f"\nwrote {len(ordered_selected)} rows to {DST}")
