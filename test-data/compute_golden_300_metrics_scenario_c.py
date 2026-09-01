#!/usr/bin/env python3
"""Closed-mode Scenario C ("Maven Central stays a blind spot, all 9 other registries mirrored")
recall/correctness measurement against golden-300.csv, per docs/spec/closed-mode-backlog.md
item 173 and docs/spec/closed-mode-plan.md Sec.5-4/Sec.6-2.

Background: Sec.6-2's Scenario C row (identification recall 247/268=92.16%, correctness rate
270/298=90.60%) was, until this script existed, *manually-arrived-at arithmetic*
(presumably: 267 S0-identified rows minus 20 maven-registry-only rows = 247), not a
reproducible measurement -- test-data/compute_golden_300_metrics_job195.py (the script Sec.6-2
cited as its source) only ever reproduced the S0 baseline; it has no code path that removes or
degrades any registry signal. This script adds that missing simulation and runs it against
test-data/job196_results.csv (the more complete real-devDB run -- Stage4 ran to full
AI-eligible coverage, vs. job195's partial ~34% Stage4 coverage; a prior investigation
confirmed job195 and job196 have identical IDENTIFIED/UNIDENTIFIED outcome buckets row-for-row,
so S0 recall should not differ between the two runs).

Simulation rule (Scenario C): Maven Central is the one registry with no mirror plan (Sec.5-4).
For every actual-results row whose actual `ecosystem` is "maven" AND that has no
independently-corroborated `cpe` value, the identification is treated as lost -- its outcome is
flipped to UNIDENTIFIED (ecosystem/package_name/cpe/confidence cleared) before scoring. A maven
row that also carries a corroborating `cpe` value is NOT flipped: per
Stage1IdentificationService#resolveCandidates's own cpeCorroboratesRegistryPackage check
(backend/src/main/java/com/vulncheck/app/service/Stage1IdentificationService.java, ~line 601),
a `cpe` riding alongside a trusted registry match must *independently* corroborate that match's
package -- it comes from the local CPE dictionary trigram search over the item's own
product_name/vendor, a code path that runs regardless of whether the Maven Central registry
lookup itself succeeded or even exists. So a maven row with a corroborating CPE would still
resolve via the CPE-only path even with Maven Central entirely gone; only registry-only maven
rows (no cpe) are actually lost.

Measured against job196 (see the printed "maven flip" line below): every actual
ecosystem=="maven" row in this dataset has an empty `cpe` field (0/20 carry a corroborating
CPE), so in practice the rule above flips exactly the 20 golden-300 maven-registry rows counted
in Sec.6-1's "maven 20" breakdown -- there is no partial/ambiguous case to adjudicate in this
particular dataset.

Everything else -- the identification-recall/correctness-rate/high-confidence definitions, the
EXCLUDED_FROM_CORRECTNESS overrides, the expected-CPE-part check, the control-row false-positive
handling -- is copied verbatim (as a shared scoring function) from
test-data/compute_golden_300_metrics_job195.py so Scenario C numbers are directly comparable to
the S0 baseline and to prior job195-based reporting. This script does not modify or replace that
existing script; job195 remains a standalone historical reproduction of S0 only.

Usage: python3 test-data/compute_golden_300_metrics_scenario_c.py
(reads test-data/golden-300.csv and test-data/job196_results.csv; no arguments, no network, no
DB access -- pure CSV recomputation, matching the existing job195 script's own invocation style.)
"""
import csv
import re

GOLDEN_300_PATH = "test-data/golden-300.csv"
ACTUAL_RESULTS_PATH = "test-data/job196_results.csv"

with open(GOLDEN_300_PATH, newline="") as f:
    expected_reader = csv.DictReader(f)
    if "ground_truth_source" not in (expected_reader.fieldnames or []):
        raise ValueError(
            f"{GOLDEN_300_PATH} is missing the 'ground_truth_source' column -- "
            f"found columns: {expected_reader.fieldnames}"
        )
    expected_rows = list(expected_reader)

with open(ACTUAL_RESULTS_PATH, newline="") as f:
    actual_reader = csv.DictReader(f)
    required_cols = {"product_name", "version", "status", "ecosystem", "cpe"}
    missing_cols = required_cols - set(actual_reader.fieldnames or [])
    if missing_cols:
        raise ValueError(
            f"{ACTUAL_RESULTS_PATH} is missing expected column(s) {missing_cols} -- "
            f"found columns: {actual_reader.fieldnames}"
        )
    actual_rows_raw = list(actual_reader)

print(f"expected rows: {len(expected_rows)}, actual rows ({ACTUAL_RESULTS_PATH}): {len(actual_rows_raw)}")

actual_by_key_s0 = {(r["product_name"], r["version"]): r for r in actual_rows_raw}

missing = [e for e in expected_rows if (e["product_name"], e["version"]) not in actual_by_key_s0]
print(f"expected rows with no matching actual row: {len(missing)}")
for m in missing:
    print("  MISSING:", m["product_name"], m["version"])


# --- Scenario C transform -----------------------------------------------------------------
# Build a second actual_by_key where every registry-only (no corroborating cpe) maven row has
# its outcome flipped to UNIDENTIFIED, simulating "Maven Central registry lookup unavailable,
# no mirror replacement, and no independent CPE-dictionary corroboration to fall back on".
maven_total = 0
maven_flipped = 0
maven_kept_via_cpe = []
actual_by_key_scenario_c = {}
for key, r in actual_by_key_s0.items():
    if r.get("ecosystem") == "maven":
        maven_total += 1
        if not r.get("cpe"):
            maven_flipped += 1
            flipped = dict(r)
            flipped["status"] = "UNIDENTIFIED"
            flipped["ecosystem"] = ""
            flipped["package_name"] = ""
            flipped["cpe"] = ""
            flipped["confidence"] = ""
            actual_by_key_scenario_c[key] = flipped
            continue
        else:
            maven_kept_via_cpe.append(key)
    actual_by_key_scenario_c[key] = r

print(f"\nScenario C maven flip: {maven_total} actual maven-ecosystem rows total, "
      f"{maven_flipped} flipped to UNIDENTIFIED (registry-only, no corroborating cpe), "
      f"{len(maven_kept_via_cpe)} kept (corroborating cpe present): {maven_kept_via_cpe}")


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


# Same annotation-driven part check as compute_golden_300_metrics_job195.py (task-backlog.md
# item 40) -- copied verbatim so Scenario C correctness scoring is directly comparable to S0.
EXPECTED_PART_RE = re.compile(r"\(part=([aoh])\b")


def expected_cpe_part(ground_truth_source):
    if not ground_truth_source:
        return None
    m = EXPECTED_PART_RE.search(ground_truth_source)
    return m.group(1) if m else None


# Same exclusions as compute_golden_300_metrics_job195.py -- genuine ground-truth ambiguities
# unrelated to the registry-mirroring question this script exists to answer. Copied verbatim
# (not imported) to keep this script a standalone, independently-auditable reproduction; see
# that script's own comment / test-data/golden-300.design.md "Post-run CPE ambiguity findings"
# for the full rationale.
EXCLUDED_FROM_CORRECTNESS = {
    ("Kibana", "8.14.3"): "elastic:kibana (app) vs elasticsearch:kibana (ours) -- both are large, "
                           "plausible dictionary entries; version-range check inconclusive.",
    ("Ditto", "3.24.234.0"): "genuine name collision between two unrelated real products both "
                              "named 'Ditto' (the clipboard-manager utility this row intended, "
                              "and the real Eclipse Foundation IoT project 'Eclipse Ditto', which "
                              "the app matched) -- not resolvable from product_name alone.",
}


def compute_metrics(label, actual_by_key):
    """Scores expected_rows against actual_by_key using exactly the same logic as
    compute_golden_300_metrics_job195.py's top-level script body -- factored into a function
    here purely so it can be run twice (S0 baseline, then Scenario C) against the same
    golden-300.csv without duplicating the logic itself. No scoring rule differs from that
    script; only which actual_by_key is scored against differs between calls."""
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

    print(f"\n=== METRICS ({label}, golden-300.csv, n={total}, scored_n={scored_total}) ===")
    print(f"(a) Identification recall over the {identification_target_total} identification-target "
          f"rows ({total} total minus {control_row_total} UNIDENTIFIED control rows): "
          f"{identification_target_identified}/{identification_target_total} = "
          f"{identification_target_identified/identification_target_total:.4f}")
    print(f"(a-fp) Control-row false-positive rate ({control_row_total} UNIDENTIFIED control rows): "
          f"{len(control_row_false_positive_rows)}/{control_row_total} = "
          f"{len(control_row_false_positive_rows)/control_row_total:.4f}")
    print(f"(b) Correctness rate (actual matches expected / {scored_total} scored rows, "
          f"{total - scored_total} excluded): "
          f"{correct_count}/{scored_total} = {correct_count/scored_total:.4f}")
    print(f"(c) High-confidence correctness rate, STRICT (confidence>=0.95 AND correct / "
          f"{scored_total} scored rows): {high_conf_correct_count}/{scored_total} = "
          f"{high_conf_correct_count/scored_total:.4f}")
    print(f"(c-alt) Same but counting a correct UNIDENTIFIED rejection as trivially "
          f"high-confidence-correct: {high_conf_correct_incl_unidentified_count}/{scored_total} = "
          f"{high_conf_correct_incl_unidentified_count/scored_total:.4f}")

    print(f"\nRows excluded from correctness scoring (still counted in identification rate): {len(excluded_rows_report)}")
    for key, status, note in excluded_rows_report:
        print(f"  EXCLUDED: {key} actual_status={status} -- {note}")

    print(f"\nFalse positives (IDENTIFIED but wrong): {len(false_positive_rows)}")
    for fp in false_positive_rows:
        print("  FP:", fp)

    print(f"\nControl-row false positives only: {len(control_row_false_positive_rows)}")
    for cfp in control_row_false_positive_rows:
        print("  CONTROL-FP:", cfp)

    print(f"\nFalse negatives (expected IDENTIFIED_* but actual UNIDENTIFIED, or no row found): {len(false_negative_rows)}")
    for fn in false_negative_rows:
        print("  FN:", fn)

    print("\n=== Per-expected_outcome breakdown ===")
    for k, v in outcome_breakdown.items():
        print(f"  {k}: {v['correct']}/{v['total']} correct")

    return {
        "identification_recall": (identification_target_identified, identification_target_total),
        "correctness_rate": (correct_count, scored_total),
    }


s0_metrics = compute_metrics(f"S0 baseline, {ACTUAL_RESULTS_PATH}, unmodified", actual_by_key_s0)
scenario_c_metrics = compute_metrics(
    f"Scenario C, {ACTUAL_RESULTS_PATH}, Maven-registry-only rows flipped to UNIDENTIFIED",
    actual_by_key_scenario_c)

print("\n=== Summary ===")
a_num, a_den = s0_metrics["identification_recall"]
b_num, b_den = s0_metrics["correctness_rate"]
print(f"S0:         identification recall {a_num}/{a_den} = {a_num/a_den:.4f}, "
      f"correctness rate {b_num}/{b_den} = {b_num/b_den:.4f}")
a_num, a_den = scenario_c_metrics["identification_recall"]
b_num, b_den = scenario_c_metrics["correctness_rate"]
print(f"Scenario C: identification recall {a_num}/{a_den} = {a_num/a_den:.4f}, "
      f"correctness rate {b_num}/{b_den} = {b_num/b_den:.4f}")
