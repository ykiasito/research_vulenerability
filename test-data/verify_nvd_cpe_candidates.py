#!/usr/bin/env python3
"""One-off ground-truth verification tool for test-data/golden-300.csv's IDENTIFIED_CPE and
UNIDENTIFIED-desktop rows: queries the public NVD CPE dictionary API (no API key; public rate
limit is 5 requests/30s) with a keyword search per candidate product name, and dumps the
returned cpeName / titles so a human (this script's caller) can pick the correct
vendor:product pair or confirm zero relevant hits. This is NOT the app's own NVD client —
it's an independent check per test-design-policy.md P1 ("do not write back the system's own
output as ground truth"). Sleeps 6.5s between requests to stay under the public rate limit.

Paging fix (2026-08-29, senior-reviewer item 1): the original version queried with
resultsPerPage=15 and stopped collecting distinct vendor:product pairs once it had seen 8 of
them (`if count >= 8: break`). For a broad/generic keyword this silently discarded the true
answer: querying "blender" returns totalResults=232, but the first 15 results (mostly
unrelated WordPress "tweet-blender" plugin CPEs) already fill the 8-pair cap before the real
`blender:blender` entry (which does exist, 159 dictionary entries) is ever reached -- the tool
reported "0 relevant results" for Blender and Rufus purely because of this truncation, not
because the CPE dictionary entry doesn't exist. Fixed by (a) reading `totalResults` and
looping over `startIndex` until every page has been fetched, and (b) removing the `count >= 8`
early-exit entirely so every distinct vendor:product pair in the full result set is captured
and written to the TSV, however many there are. `resultsPerPage` is also raised from 15 to 200
(NVD's documented max for this endpoint is 10,000; 200 comfortably covers every candidate this
project has queried so far in a single page while keeping each response body small) so most
searches still complete in one request; the startIndex loop below is what actually guarantees
correctness for the rare candidate whose totalResults exceeds one page, not the page size.
"""
import json
import sys
import time
import urllib.request
import urllib.parse

UA = "vulncheck-research-golden300-dataset-builder/1.0 (+internal research tool, non-commercial)"
SLEEP_S = 6.5
RESULTS_PER_PAGE = 200


def fetch_page(keyword, start_index):
    url = ("https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch="
           + urllib.parse.quote(keyword)
           + "&resultsPerPage=" + str(RESULTS_PER_PAGE)
           + "&startIndex=" + str(start_index))
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8")), url


def search_all_pages(keyword):
    """Fetches every page of results for `keyword`, sleeping SLEEP_S between page requests
    (including the first, so callers can just call this once per keyword in a loop without
    their own extra sleep). Returns (all_products, total_results, first_page_url)."""
    all_products = []
    start_index = 0
    total = None
    first_url = None
    while True:
        data, url = fetch_page(keyword, start_index)
        if first_url is None:
            first_url = url
        if total is None:
            total = data.get("totalResults", 0)
        products = data.get("products", [])
        all_products.extend(products)
        start_index += RESULTS_PER_PAGE
        if start_index >= total or not products:
            break
        time.sleep(SLEEP_S)
    return all_products, total, first_url


# Hardcoded, not CLI args (this project's shell-command allowlist only covers bare
# `python3 test-data/<file>.py` invocations, no arguments) -- edit this list and re-run for
# each batch instead of passing candidates on the command line.
CANDIDATES = [
    "slack desktop",
    "blender",
    "OBS Studio",
    "WinDirStat",
    "rufus",
    "ExamDiff Pro",
    "Bulk Rename Utility",
    "WizTree",
    "Directory Opus",
    "ShareX",
    "ClipboardFusion",
    "Q-Dir",
    "XYplorer",
    "Ditto clipboard manager",
    "Process Hacker",
]

out_path = "test-data/golden300_cpe_results.tsv"
with open(out_path, "a") as out:
    for kw in CANDIDATES:
        try:
            products, total, url = search_all_pages(kw)
            print(f"=== {kw} === total={total} url={url}")
            out.write(f"=== {kw} === total={total} url={url}\n")
            seen = set()
            count = 0
            for p in products:
                cpe = p.get("cpe", {})
                name = cpe.get("cpeName", "")
                title = ""
                for t in cpe.get("titles", []):
                    if t.get("lang") == "en":
                        title = t.get("title", "")
                        break
                # cpe:2.3:a:vendor:product:version:...
                parts = name.split(":")
                vp = (parts[3], parts[4]) if len(parts) > 4 else ("", "")
                if vp in seen:
                    continue
                seen.add(vp)
                count += 1
                line = f"    {name}  |  {title}"
                print(line)
                out.write(line + "\n")
            print(f"    ({count} distinct vendor:product pairs across {total} total results)")
            out.write(f"    ({count} distinct vendor:product pairs across {total} total results)\n")
        except Exception as e:
            line = f"=== {kw} === ERROR {type(e).__name__}: {e}"
            print(line)
            out.write(line + "\n")
        out.flush()
        time.sleep(SLEEP_S)
print(f"\nAppended to {out_path}")
