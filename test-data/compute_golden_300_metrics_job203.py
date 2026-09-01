#!/usr/bin/env python3
"""Computes the goal-2 accuracy metrics (identification recall, correctness rate,
high-confidence correctness rate) + false-positive/false-negative counts for job 203
(golden-300.csv run), by joining test-data/golden-300.csv's expected_* ground-truth columns
against an export of job 203's actual research_job_items + identified_products rows
(test-data/job203_results.csv, produced via a one-off `\\COPY ... TO STDOUT` from the real dev DB
-- read-only, no writes).

Job 203 context (2026-09-01, closed-mode-backlog.md item 172): a static-only (Tier1, no AI
tier -- user_id=5 has only the nvd secret, no claude secret, at the time of this run) re-run of
the golden-300 benchmark against the real dev DB, to confirm PR#91/backlog item 166's Stage1
extraction (Stage1RegistryIdentification/Stage1AiArbitration split out of
Stage1IdentificationService, claimed zero behavior change) introduced no regression relative to
job191's baseline. Same methodology as test-data/compute_golden_300_metrics_job195.py (see that
file's docstring for the full history of the metric-definition fix and the part=a|o|h check),
just repointed at job 203's own export. This is a free Tier1-only regression-check proxy, not
the v1.0-gate AI-included accuracy measurement (that's job195/196 -- see
docs/spec memory project_v1_gate_metric_clarification_2026-08-30 for why the two must not be
conflated).
"""
import csv
import re

with open("test-data/golden-300.csv", newline="") as f:
    expected_reader = csv.DictReader(f)
    # ground_truth_source drives the part=a|o|h check below (task-backlog.md item 40) --
    # fail loudly on a malformed/renamed CSV instead of expected_cpe_part() silently
    # returning None for every row and the part check silently no-op'ing.
    if "ground_truth_source" not in (expected_reader.fieldnames or []):
        raise ValueError(
            "test-data/golden-300.csv is missing the 'ground_truth_source' column -- "
            f"found columns: {expected_reader.fieldnames}"
        )
    expected_rows = list(expected_reader)

with open("test-data/job203_results.csv", newline="") as f:
    actual_rows = list(csv.DictReader(f))

print(f"expected rows: {len(expected_rows)}, actual rows: {len(actual_rows)}")

# Build actual lookup keyed by (product_name, version) -- verified unique in golden-300.csv.
actual_by_key = {}
for r in actual_rows:
    key = (r["product_name"], r["version"])
    actual_by_key[key] = r

missing = [e for e in expected_rows if (e["product_name"], e["version"]) not in actual_by_key]
print(f"expected rows with no matching actual row: {len(missing)}")
for m in missing:
    print("  MISSING:", m["product_name"], m["version"])


def cpe_vendor_product(cpe_string):
    if not cpe_string:
        return None, None
    parts = cpe_string.split(":")
    # cpe:2.3:PART:VENDOR:PRODUCT:...
    if len(parts) < 5:
        return None, None
    return parts[3], parts[4]


def cpe_part(cpe_string):
    if not cpe_string:
        return None
    parts = cpe_string.split(":")
    # cpe:2.3:PART:VENDOR:PRODUCT:...
    if len(parts) < 3:
        return None
    return parts[2]


# task-backlog.md item 40 (2026-08-30): the vendor/product-only comparison above cannot
# catch a part (a/o/h) mismatch -- e.g. a CVE-vendor:product-correct match that was actually
# built or selected with the wrong CPE part (item 39's CpeUtils.buildCpe part=a-fixed bug,
# item 49's part=a-preference dedup CASE) would still score as "correct" here even though the
# app queried/returned the wrong real-world CPE. golden-300.csv has no dedicated structured
# expected-part column (adding verified ground truth for all 268 IDENTIFIED_CPE rows is out of
# this task's scope), but a handful of rows already carry a manually NVD-verified
# "(part=a|o|h" annotation in their free-text ground_truth_source column (Cisco IOS XE, PAN-OS,
# MikroTik RouterOS, Metasploit Framework -- see golden-300.design.md). Where that annotation is
# present, treat it as authoritative structured ground truth and fail the row if the actual
# identified CPE's part disagrees, even when vendor:product still match. Where it's absent, skip
# the part check entirely (no assumption is made, no existing correct row can be newly failed by
# this change).
EXPECTED_PART_RE = re.compile(r"\(part=([aoh])\b")


def expected_cpe_part(ground_truth_source):
    if not ground_truth_source:
        return None
    m = EXPECTED_PART_RE.search(ground_truth_source)
    return m.group(1) if m else None


# Rows excluded from correctness/high-confidence scoring only (still count toward the
# identification-rate denominator): genuine, post-hoc-discovered ground-truth ambiguities
# that a live cpeMatchString re-check (test-data/verify_cpe_match_string.py) could not
# resolve one way or the other -- scoring them either way would misrepresent the app's
# actual accuracy. See test-data/golden-300.design.md "Post-run CPE ambiguity findings".
EXCLUDED_FROM_CORRECTNESS = {
    ("Kibana", "8.14.3"): "elastic:kibana (app) vs elasticsearch:kibana (ours) -- both are large, "
                           "plausible dictionary entries; version-range check inconclusive.",
    ("Ditto", "3.24.234.0"): "genuine name collision between two unrelated real products both "
                              "named 'Ditto' (the clipboard-manager utility this row intended, "
                              "and the real Eclipse Foundation IoT project 'Eclipse Ditto', which "
                              "the app matched) -- not resolvable from product_name alone.",
}

total = len(expected_rows)
identified_count = 0
correct_count = 0
high_conf_correct_count = 0
high_conf_correct_incl_unidentified_count = 0
false_positive_rows = []
false_negative_rows = []
correct_but_low_conf_rows = []
outcome_breakdown = {"IDENTIFIED_REGISTRY": {"total": 0, "correct": 0},
                      "IDENTIFIED_CPE": {"total": 0, "correct": 0},
                      "UNIDENTIFIED": {"total": 0, "correct": 0}}

excluded_rows_report = []
scored_total = 0

# Identification-target rows are every row NOT in the UNIDENTIFIED control bucket -- these are
# the rows a correctly-functioning pipeline is expected to actually identify (recall
# denominator, item 8). Counted dynamically from the CSV rather than hardcoded, so this stays
# correct if the control-row count ever changes again (as it just did: 34 -> 32 after the
# Blender/Rufus correction, see design note).
control_row_total = sum(1 for e in expected_rows if e["expected_outcome"] == "UNIDENTIFIED")
identification_target_total = total - control_row_total
identification_target_identified = 0  # numerator: of the target rows, how many came back IDENTIFIED (regardless of correctness -- this is a recall-of-attempt metric, not a recall-of-correctness metric; correctness is (b)/(c) below)
control_row_false_positive_rows = []  # control rows that came back IDENTIFIED anyway

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

    # Recall (identification_target_identified) and the control-row false-positive count must
    # be computed for EVERY row with an actual result, including the 2 rows in
    # EXCLUDED_FROM_CORRECTNESS (Kibana, Ditto) -- design.md "Post-run CPE ambiguity findings"
    # / "Correction-effect arithmetic" explicitly says both rows count toward the recall
    # numerator/denominator per their own bucket even though they're excluded from
    # correctness/high-confidence scoring.
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
        # Registries canonicalize package-name casing differently (PyPI's "Flask" vs the
        # commonly-typed "flask" are the same package); case-insensitive compare here, exact
        # compare on ecosystem (a small fixed, already-lowercase vocabulary).
        correct = (is_identified
                   and ecosystem_actual == e["expected_ecosystem"]
                   and package_actual.lower() == e["expected_package_name"].lower())
    elif expected_outcome == "IDENTIFIED_CPE":
        cv, cp = cpe_vendor_product(cpe_actual)
        exp_part = expected_cpe_part(e.get("ground_truth_source", ""))
        part_ok = exp_part is None or cpe_part(cpe_actual) == exp_part
        correct = (is_identified
                   and cv == e["expected_cpe_vendor"]
                   and cp == e["expected_cpe_product"]
                   and part_ok)
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
            high_conf_correct_incl_unidentified_count += 1
        elif expected_outcome == "UNIDENTIFIED":
            # no confidence concept for a correct rejection; counted separately below
            high_conf_correct_incl_unidentified_count += 1
        else:
            correct_but_low_conf_rows.append((e["product_name"], e["version"], confidence_actual))
    else:
        if is_identified:
            false_positive_rows.append((e["product_name"], e["version"], expected_outcome,
                                         ecosystem_actual, package_actual, cpe_actual,
                                         e.get("expected_ecosystem"), e.get("expected_package_name"),
                                         e.get("expected_cpe_vendor"), e.get("expected_cpe_product")))
        else:
            false_negative_rows.append((e["product_name"], e["version"], expected_outcome))

print(f"\n=== METRICS (job 203, golden-300.csv, static Tier1-only pipeline, n={total}, scored_n={scored_total}) ===")
print(f"(a) Identification recall over the {identification_target_total} identification-target "
      f"rows ({total} total minus {control_row_total} UNIDENTIFIED control rows): "
      f"{identification_target_identified}/{identification_target_total} = "
      f"{identification_target_identified/identification_target_total:.4f}")
print(f"(a-fp) Control-row false-positive rate ({control_row_total} UNIDENTIFIED control rows, "
      f"how often the pipeline wrongly claims an identification for something with no real "
      f"vulnerability-data anchor): {len(control_row_false_positive_rows)}/{control_row_total} = "
      f"{len(control_row_false_positive_rows)/control_row_total:.4f}")
print(f"(a-old, deprecated) Identification rate, old definition (IDENTIFIED / {total}, kept "
      f"here only for historical comparison to the pre-2026-08-29-fix number, not a metric to "
      f"report going forward): {identified_count}/{total} = {identified_count/total:.4f}")
print(f"(b) Correctness rate (actual matches expected / {scored_total} scored rows, "
      f"{total - scored_total} excluded -- see below): "
      f"{correct_count}/{scored_total} = {correct_count/scored_total:.4f}")
print(f"(c) High-confidence correctness rate, STRICT (confidence>=0.95 AND correct / "
      f"{scored_total} scored rows, UNIDENTIFIED-correct rows excluded since they carry no "
      f"confidence value): {high_conf_correct_count}/{scored_total} = "
      f"{high_conf_correct_count/scored_total:.4f}")
print(f"(c-alt) Same but counting a correct UNIDENTIFIED rejection as trivially "
      f"high-confidence-correct: {high_conf_correct_incl_unidentified_count}/{scored_total} = "
      f"{high_conf_correct_incl_unidentified_count/scored_total:.4f}")

print(f"\nRows excluded from correctness scoring (still counted in identification rate): {len(excluded_rows_report)}")
for key, status, note in excluded_rows_report:
    print(f"  EXCLUDED: {key} actual_status={status} -- {note}")

print(f"\nFalse positives (IDENTIFIED but wrong -- includes wrongly-identified UNIDENTIFIED-expected rows): {len(false_positive_rows)}")
for fp in false_positive_rows:
    print("  FP:", fp)

print(f"\nControl-row false positives only (subset of the above, expected_outcome=UNIDENTIFIED "
      f"rows that came back IDENTIFIED -- see (a-fp) above): {len(control_row_false_positive_rows)}")
for cfp in control_row_false_positive_rows:
    print("  CONTROL-FP:", cfp)

print(f"\nFalse negatives (expected IDENTIFIED_* but actual UNIDENTIFIED, or no row found): {len(false_negative_rows)}")
for fn in false_negative_rows:
    print("  FN:", fn)

print(f"\nCorrect matches but confidence < 0.95 (or no confidence recorded): {len(correct_but_low_conf_rows)}")
for c in correct_but_low_conf_rows:
    print("  LOWCONF:", c)

print("\n=== Per-expected_outcome breakdown ===")
for k, v in outcome_breakdown.items():
    print(f"  {k}: {v['correct']}/{v['total']} correct")
