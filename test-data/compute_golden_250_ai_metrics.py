#!/usr/bin/env python3
"""Computes goal-2 accuracy metrics (identification recall, correctness rate, high-confidence
correctness rate) for the first AI-included run of the golden-300 benchmark (job 189,
2026-08-29), against the stratified 250-item subsample `golden-250-ai-test.csv`
(test-data/sample_golden_250.py, seed 20260829).

Job 168 (the only prior run of this dataset, static-only -- no Claude key configured for its
user) is the only other real run of any part of golden-300.csv, so this script also recomputes
the SAME metrics over job 168's results but restricted to the same 250 (product_name, version)
keys as this run, so the AI-included vs static-only comparison is apples-to-apples (250 vs 250
scored against the same expectations) instead of comparing across different item counts and
sample compositions (250 vs 298).

Scoring logic (EXCLUDED_FROM_CORRECTNESS, recall/control-row-false-positive definitions,
correctness/high-confidence-correctness definitions) is intentionally kept identical to
compute_golden_300_metrics.py -- see that script's module docstring for the full history/
rationale of each metric definition. This is a new script, not an edit of that one, since the
input files (expected + actual) and population (250 vs 300 rows) differ.

Does not read any credentials; only reads CSV exports already produced via read-only \\COPY from
the real dev DB (test-data/job189_results.csv, test-data/job168_results.csv).
"""
import csv

EXPECTED_CSV = "test-data/golden-250-ai-test.csv"
JOB189_ACTUAL_CSV = "test-data/job189_results.csv"
JOB168_ACTUAL_CSV = "test-data/job168_results.csv"

# Same exclusion list as compute_golden_300_metrics.py (see that script for the full rationale).
# Only "Kibana"/"8.14.3" is actually present in the 250-item subsample (verified: "Ditto"/
# "3.24.234.0" was not selected by sample_golden_250.py's stratified draw) -- the entry is kept
# here anyway since a key not present in `expected_rows` is simply never looked up, doing no harm,
# and keeping the two scripts' exclusion lists textually identical avoids them silently drifting.
EXCLUDED_FROM_CORRECTNESS = {
    ("Kibana", "8.14.3"): "elastic:kibana (app) vs elasticsearch:kibana (ours) -- both are large, "
                           "plausible dictionary entries; version-range check inconclusive.",
    ("Ditto", "3.24.234.0"): "genuine name collision between two unrelated real products both "
                              "named 'Ditto' (the clipboard-manager utility this row intended, "
                              "and the real Eclipse Foundation IoT project 'Eclipse Ditto', which "
                              "the app matched) -- not resolvable from product_name alone.",
}


def cpe_vendor_product(cpe_string):
    if not cpe_string:
        return None, None
    parts = cpe_string.split(":")
    if len(parts) < 5:
        return None, None
    return parts[3], parts[4]


def score(expected_rows, actual_rows, label):
    actual_by_key = {(r["product_name"], r["version"]): r for r in actual_rows}

    missing = [e for e in expected_rows if (e["product_name"], e["version"]) not in actual_by_key]

    total = len(expected_rows)
    identified_count = 0
    correct_count = 0
    high_conf_correct_count = 0
    false_positive_rows = []
    false_negative_rows = []
    correct_but_low_conf_rows = []
    outcome_breakdown = {"IDENTIFIED_REGISTRY": {"total": 0, "correct": 0},
                          "IDENTIFIED_CPE": {"total": 0, "correct": 0},
                          "UNIDENTIFIED": {"total": 0, "correct": 0}}

    excluded_rows_report = []
    scored_total = 0

    control_row_total = sum(1 for e in expected_rows if e["expected_outcome"] == "UNIDENTIFIED")
    identification_target_total = total - control_row_total
    identification_target_identified = 0
    control_row_false_positive_rows = []

    for e in expected_rows:
        key = (e["product_name"], e["version"])
        a = actual_by_key.get(key)
        expected_outcome = e["expected_outcome"]

        if a is None:
            false_negative_rows.append((e["product_name"], e["version"], "NO ACTUAL ROW FOUND"))
            outcome_breakdown[expected_outcome]["total"] += 1
            scored_total += 1
            continue

        actual_status = a["status"]
        is_identified = actual_status == "IDENTIFIED"

        if is_identified:
            identified_count += 1
            if expected_outcome != "UNIDENTIFIED":
                identification_target_identified += 1
            else:
                control_row_false_positive_rows.append((e["product_name"], e["version"],
                                                          a.get("ecosystem", ""), a.get("package_name", ""),
                                                          a.get("cpe", "")))

        if key in EXCLUDED_FROM_CORRECTNESS:
            excluded_rows_report.append((key, actual_status, EXCLUDED_FROM_CORRECTNESS[key]))
            continue

        outcome_breakdown[expected_outcome]["total"] += 1
        scored_total += 1

        ecosystem_actual = a.get("ecosystem", "")
        package_actual = a.get("package_name", "")
        cpe_actual = a.get("cpe", "")
        confidence_actual = a.get("confidence", "")

        correct = False
        if expected_outcome == "IDENTIFIED_REGISTRY":
            correct = (is_identified
                       and ecosystem_actual == e["expected_ecosystem"]
                       and package_actual.lower() == e["expected_package_name"].lower())
        elif expected_outcome == "IDENTIFIED_CPE":
            cv, cp = cpe_vendor_product(cpe_actual)
            correct = (is_identified
                       and cv == e["expected_cpe_vendor"]
                       and cp == e["expected_cpe_product"])
        elif expected_outcome == "UNIDENTIFIED":
            correct = (actual_status == "UNIDENTIFIED")

        if correct:
            correct_count += 1
            outcome_breakdown[expected_outcome]["correct"] += 1
            try:
                conf = float(confidence_actual) if confidence_actual else None
            except ValueError:
                conf = None
            if conf is not None and conf >= 0.95:
                high_conf_correct_count += 1
            elif expected_outcome != "UNIDENTIFIED":
                correct_but_low_conf_rows.append((e["product_name"], e["version"], confidence_actual))
        else:
            if is_identified:
                false_positive_rows.append((e["product_name"], e["version"], expected_outcome,
                                             ecosystem_actual, package_actual, cpe_actual))
            else:
                false_negative_rows.append((e["product_name"], e["version"], expected_outcome))

    print(f"\n=== METRICS ({label}, n={total}, scored_n={scored_total}) ===")
    print(f"expected rows with no matching actual row: {len(missing)}")
    for m in missing:
        print("  MISSING:", m["product_name"], m["version"])
    print(f"(a) Identification recall over {identification_target_total} identification-target rows "
          f"({total} total minus {control_row_total} UNIDENTIFIED control rows): "
          f"{identification_target_identified}/{identification_target_total} = "
          f"{identification_target_identified / identification_target_total:.4f}")
    print(f"(a-fp) Control-row false-positive rate ({control_row_total} UNIDENTIFIED control rows): "
          f"{len(control_row_false_positive_rows)}/{control_row_total} = "
          f"{(len(control_row_false_positive_rows) / control_row_total) if control_row_total else 0:.4f}")
    print(f"(b) Correctness rate: {correct_count}/{scored_total} = {correct_count / scored_total:.4f}")
    print(f"(c) High-confidence correctness rate, STRICT (confidence>=0.95 AND correct, "
          f"UNIDENTIFIED-correct rows excluded -- no confidence value): "
          f"{high_conf_correct_count}/{scored_total} = {high_conf_correct_count / scored_total:.4f}")
    print(f"Rows excluded from correctness scoring: {len(excluded_rows_report)}")
    for key, status, note in excluded_rows_report:
        print(f"  EXCLUDED: {key} actual_status={status} -- {note}")
    print(f"False positives: {len(false_positive_rows)}")
    for fp in false_positive_rows:
        print("  FP:", fp)
    print(f"Control-row false positives: {len(control_row_false_positive_rows)}")
    for cfp in control_row_false_positive_rows:
        print("  CONTROL-FP:", cfp)
    print(f"False negatives: {len(false_negative_rows)}")
    for fn in false_negative_rows:
        print("  FN:", fn)
    print(f"Correct matches but confidence < 0.95 (or no confidence recorded): {len(correct_but_low_conf_rows)}")
    for c in correct_but_low_conf_rows:
        print("  LOWCONF:", c)
    print("Per-expected_outcome breakdown:")
    for k, v in outcome_breakdown.items():
        print(f"  {k}: {v['correct']}/{v['total']} correct")

    return {
        "n": total,
        "scored_n": scored_total,
        "recall": identification_target_identified / identification_target_total,
        "correctness": correct_count / scored_total,
        "high_conf_correctness": high_conf_correct_count / scored_total,
    }


with open(EXPECTED_CSV, newline="") as f:
    expected_rows = list(csv.DictReader(f))
print(f"expected rows (golden-250-ai-test.csv): {len(expected_rows)}")

with open(JOB189_ACTUAL_CSV, newline="") as f:
    job189_rows = list(csv.DictReader(f))
print(f"job 189 (AI-included) actual rows: {len(job189_rows)}")

with open(JOB168_ACTUAL_CSV, newline="") as f:
    job168_all_rows = list(csv.DictReader(f))
expected_keys = {(e["product_name"], e["version"]) for e in expected_rows}
job168_subset_rows = [r for r in job168_all_rows if (r["product_name"], r["version"]) in expected_keys]
print(f"job 168 (static-only) actual rows, full: {len(job168_all_rows)}, "
      f"restricted to this run's {len(expected_keys)} sampled keys: {len(job168_subset_rows)}")

ai_metrics = score(expected_rows, job189_rows, "job 189, AI-included, golden-250-ai-test.csv")
static_metrics = score(expected_rows, job168_subset_rows,
                        "job 168 static-only SUBSET restricted to the same 250 sampled keys")

print("\n=== SIDE-BY-SIDE COMPARISON (same 250-item population, same scoring logic) ===")
print(f"{'metric':35s} {'static-only (job168 subset)':30s} {'AI-included (job189)':25s}")
print(f"{'correctness rate':35s} {static_metrics['correctness']:.4f} "
      f"({static_metrics['scored_n']} scored){'':10s} {ai_metrics['correctness']:.4f} "
      f"({ai_metrics['scored_n']} scored)")
print(f"{'high-confidence correctness':35s} {static_metrics['high_conf_correctness']:.4f}{'':10s} "
      f"{ai_metrics['high_conf_correctness']:.4f}")
print(f"{'identification recall':35s} {static_metrics['recall']:.4f}{'':10s} {ai_metrics['recall']:.4f}")
print("\nReference (full 300-item golden-300.csv, job 168, from golden-300.design.md): "
      "correctness 91.61% (273/298), high-confidence correctness 67.11% (200/298) -- "
      "NOT directly comparable to the 250-item numbers above (different n); the "
      "job168-subset-restricted-to-250 row above is the correct like-for-like static-only baseline.")
