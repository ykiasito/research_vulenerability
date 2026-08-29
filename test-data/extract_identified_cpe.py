import csv

SRC = "test-data/golden-300.csv"
OUT_FULL = "test-data/golden300-identified-cpe.csv"
OUT_PILOT = "test-data/golden300-identified-cpe-pilot.csv"
OUT_TRUTH = "test-data/golden300-identified-cpe-truth.csv"

UPLOAD_COLUMNS = ["product_name", "version", "vendor", "usage_text", "install_url"]

with open(SRC, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    rows = [r for r in reader if r["expected_outcome"] == "IDENTIFIED_CPE"]

print(f"Found {len(rows)} IDENTIFIED_CPE rows")

with open(OUT_FULL, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=UPLOAD_COLUMNS)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in UPLOAD_COLUMNS})

with open(OUT_PILOT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=UPLOAD_COLUMNS)
    writer.writeheader()
    for r in rows[:4]:
        writer.writerow({k: r.get(k, "") for k in UPLOAD_COLUMNS})

# Ground-truth-only lookup file (product_name+version -> expected cpe vendor/product) for later
# comparison, since the upload CSV itself doesn't carry those columns.
with open(OUT_TRUTH, "w", newline="", encoding="utf-8") as f:
    fieldnames = ["product_name", "version", "expected_cpe_vendor", "expected_cpe_product", "ground_truth_source"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in fieldnames})

print("wrote", OUT_FULL, OUT_PILOT, OUT_TRUTH)
