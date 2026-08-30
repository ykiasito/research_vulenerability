# `golden-300.csv` — Design Note

Generator: `test-data/gen_golden_300.py` (deterministic, no randomness — fully enumerated
data transcribed from two independent verification logs). Re-running the generator
reproduces the CSV byte-identically.

Verification artifacts (raw logs, not committed data, kept for audit):
- `test-data/golden300_registry_results.tsv` — 200 live registry API responses (npm, PyPI,
  Maven Central, Go module proxy, NuGet, RubyGems, crates.io, Packagist, Hex, pub.dev),
  fetched 2026-08-29 by `test-data/verify_registry_candidates.py`.
- `test-data/golden300_cpe_results.tsv` — live NVD CPE dictionary (`services.nvd.nist.gov`,
  public/unauthenticated) keyword-search responses, fetched 2026-08-29 by
  `test-data/verify_nvd_cpe_candidates.py` (paging bug fixed 2026-08-29, see "Ground-truth
  correction: Blender and Rufus" below -- full-pagination re-runs also cover the 30
  `UNIDENTIFIED` control rows, see "Verification coverage").
- `test-data/verify_cpe_match_string.py` / `test-data/verify_cpe_match_string_agreeing_rows.py`
  — `cpeMatchString`-based strong verification (confirms a vendor:product pair is a genuine,
  non-fabricated NVD CPE dictionary entry) for the 14 `IDENTIFIED_CPE` rows where job 168
  disagreed with this file, and (2026-08-29, item 5) the 53 rows where it agreed, respectively.
  The 53-agreeing-rows check's output is persisted at
  `test-data/golden300_cpe_matchstring_results.tsv` (2026-08-29, senior-reviewer re-review
  item 5 -- previously stdout-only, with no on-disk record unlike the other two tsv files
  above; re-run and confirmed 0/53 with `totalResults=0`).

## Purpose

The first正解-labeled (ground-truth) accuracy benchmark for this project's 1.0-gate goal 2
(static precision, Stage1/Tier1 only, no AI). Unlike `test-data/real-1000.csv` (which has
no expected-outcome columns at all) and `Stage1GoldenBenchmarkTest`'s CSV (mocked registry
input, not end-to-end), every row here carries an independently verified expected outcome,
so identification-rate, correctness-rate, and high-confidence-correctness-rate can all be
computed against a real answer key.

**Ground-truth policy (test-design-policy.md P1, explicit per this task's brief): no row's
expected_outcome/expected_ecosystem/expected_package_name/expected_cpe_vendor/
expected_cpe_product was copied from this app's own prior output.** Every value was
independently obtained by directly querying the relevant public registry API or the NVD CPE
dictionary API on 2026-08-29, months/some point after `real-1000.csv`/`real-400.csv` were
authored, and recorded with the exact query URL in `ground_truth_source` (mandatory,
non-blank on every one of the 300 rows).

## The app's supported registries (11, not 10)

**Corrected 2026-08-29 (senior-reviewer review item 6).** Earlier drafts of this note
described "the 10 supported package registries" as if that were the complete list. It is not
— the app has an 11th: `ChocolateyRegistryClient.java`
(`backend/src/main/java/com/vulncheck/app/service/registry/ChocolateyRegistryClient.java`),
added to cover desktop-installer software (OBS Studio, HandBrake, Slack, Docker Desktop, ...)
that the other 10 — all language/library package managers — never had any chance of
identifying. The full, current list (one `PackageRegistryLookup` implementation each, all in
`backend/src/main/java/com/vulncheck/app/service/registry/`):

| # | Ecosystem string | Client | OSV-backed (vulnerability data fetched)? |
|---|---|---|---|
| 1 | `npm` | `NpmRegistryClient` | Yes |
| 2 | `pypi` | `PyPiRegistryClient` | Yes |
| 3 | `maven` | `MavenCentralRegistryClient` | Yes |
| 4 | `go` | `GoProxyRegistryClient` | Yes |
| 5 | `nuget` | `NuGetRegistryClient` | Yes |
| 6 | `rubygems` | `RubyGemsRegistryClient` | Yes |
| 7 | `crates.io` | `CratesIoRegistryClient` | Yes |
| 8 | `packagist` | `PackagistRegistryClient` | Yes |
| 9 | `hex` | `HexRegistryClient` | Yes |
| 10 | `pub` | `PubRegistryClient` | Yes |
| 11 | `chocolatey` | `ChocolateyRegistryClient` | **No** |

The "Yes" column is confirmed from `OsvSyncService.SUPPORTED_OSV_ECOSYSTEMS`
(`backend/src/main/java/com/vulncheck/app/service/osv/OsvSyncService.java:71`) — exactly the
10 OSV-native ecosystems this app mirrors and fetches CVE/GHSA-sourced vulnerability data for.
Chocolatey is not an OSV ecosystem and has no CPE dictionary either; a Chocolatey match
produces a `pkg:chocolatey/...` purl with no linked vulnerability source at all. This matters
directly for the `UNIDENTIFIED` control bucket below (see "Chocolatey and the UNIDENTIFIED
control bucket").

## Row count and composition

**Total: 300 rows.**

| Category | Rows | expected_outcome |
|---|---|---|
| Registry packages (10 OSV-backed ecosystems x 20) | 200 | `IDENTIFIED_REGISTRY` |
| Job-167 regression checks (mandated by task) | 8 | 4x `IDENTIFIED_CPE`, 4x `UNIDENTIFIED` (see below — verification overturned the "probably IDENTIFIED_CPE" assumption for half of them) |
| Other real desktop/CLI software with a confirmed NVD CPE entry | 62 | `IDENTIFIED_CPE` |
| Blender / Rufus (corrected 2026-08-29 — see "Ground-truth correction: Blender and Rufus") | 2 | `IDENTIFIED_CPE` |
| Fictional products (never existed) | 15 | `UNIDENTIFIED` |
| Real products confirmed absent from both the CPE dictionary and all 10 OSV-backed registries | 13 | `UNIDENTIFIED` |

**expected_outcome totals: `IDENTIFIED_REGISTRY`=200, `IDENTIFIED_CPE`=68 (62+4+2), `UNIDENTIFIED`=32 (4+15+13).** 200+68+32=300.

(Originally 66/34 before the Blender/Rufus correction moved 2 rows from `UNIDENTIFIED` to
`IDENTIFIED_CPE` — see below.)

Distinct `product_name` count: **299** (one intentional cross-registry generic-name
collision: `uuid` appears twice — once as the npm package `uuid` 14.0.2, once as the Rust
crate `uuid` 1.26.0 — a real, independently-verified adversarial case per policy P4, not a
duplication bug; the two rows have different versions and different expected ecosystems).

### Per-ecosystem breakdown (registry segment, 200 rows)

20 rows each: npm, PyPI, Maven Central, Go module proxy, NuGet, RubyGems, crates.io,
Packagist, Hex, pub.dev. Every one of the 200 was a live, successful API response on
2026-08-29 (0 misses) — see `golden300_registry_results.tsv` for every query URL and
returned version. `expected_package_name` is the exact identifier the registry itself uses
(e.g. Maven's `groupId:artifactId`, Go's full module import path), matching how
`IdentifiedProduct.packageName` is actually populated per ecosystem
(`backend/src/main/java/com/vulncheck/app/service/registry/*RegistryClient.java`).
`vendor` is left empty throughout, matching `real-400.csv`'s established convention
(package registries don't carry a separate display-vendor field).

### Job-167 regression checks (8 rows) — verification result, not assumption

The task brief asked to include Cisco IOS XE, PAN-OS, MikroTik RouterOS, Android Studio,
OWASP ZAP, Metasploit Framework, Unreal Engine, and Windows Terminal — job 167's 8 false
negatives — "with the correct expected_outcome (probably IDENTIFIED_CPE), verified rather
than assumed." The verification came back split, which is itself a finding worth stating
plainly:

| Product | NVD CPE dictionary keyword search result (2026-08-29) | expected_outcome |
|---|---|---|
| Cisco IOS XE | `cpe:2.3:o:cisco:ios_xe:...` exists (part=o, an OS CPE, not part=a) | `IDENTIFIED_CPE` |
| PAN-OS | `cpe:2.3:o:paloaltonetworks:pan-os:...` exists (part=o) | `IDENTIFIED_CPE` |
| MikroTik RouterOS | `cpe:2.3:o:mikrotik:routeros:...` exists (part=o) | `IDENTIFIED_CPE` |
| Metasploit Framework | `cpe:2.3:a:rapid7:metasploit:...` exists (part=a) | `IDENTIFIED_CPE` |
| Android Studio | 0 relevant hits under multiple query phrasings (`Android Studio`, `android_studio`, `Google Android Studio IDE`) | `UNIDENTIFIED` |
| OWASP ZAP | 0 hits for `zaproxy` (actual project name); `OWASP ZAP` keyword only matches an unrelated Jenkins plugin CPE | `UNIDENTIFIED` |
| Unreal Engine | Only 1 unrelated hit (a game "for Unreal Engine"); no CPE for the engine itself | `UNIDENTIFIED` |
| Windows Terminal | 0 hits; only unrelated legacy Windows NT/2000 "Terminal Services" entries surface | `UNIDENTIFIED` |

**Implication for job 167's "8 false negatives" framing:** only half of these products were
ever identifiable in principle via the CPE dictionary at all. The other half (Android
Studio, OWASP ZAP, Unreal Engine, Windows Terminal) have no NVD CPE entry under any query
phrasing tried — for these, `UNIDENTIFIED` was always the only correct answer, and job 167
not identifying them was not a routing/name-matching bug, it was the pipeline correctly
having nothing to find. This is a materially different conclusion than the task brief's
working assumption ("おそらくIDENTIFIED_CPE"), and changes where remediation effort for
these specific products should go (none — a "fix" here would have to fabricate CPE data;
the real remaining gap is limited to the 3 `part=o` OS entries, where the open question is
whether this app's CPE matching logic considers `part=o` dictionary rows at all, not
whether the data exists).

### Other real desktop/CLI software (62 rows, `IDENTIFIED_CPE`)

Vendor:product pairs independently confirmed via live NVD CPE keyword search
(`golden300_cpe_results.tsv`); every `ground_truth_source` cell carries the exact query URL.
Versions are real, hand-curated recent releases — **not** independently re-verified against
a per-row release feed at generation time (the same version-sourcing approach
`real-400.csv`'s design note already documented and a prior reviewer accepted
PASS-with-notes for its non-registry segment), because this app's CPE identification path
matches on vendor/product, not on the specific version string being present in the sampled
CPE dictionary rows. Three rows deliberately use an old, exact version literally returned by
the API rather than a hand-picked recent one, because a plain keyword search for these three
products' *current* naming didn't clearly resolve to one unambiguous vendor:product pair
(a legitimate real-world ambiguity, not a data-quality problem):
- **Jenkins** 1.437 / `cloudbees:jenkins` (modern Jenkins governance changed vendor
  attribution over time; this exact old pairing is the one the API concretely returned).
- **Ansible** 1.1 / `ansibleworks:ansible` (distinct from the separately-dictionaried
  `ansible:tower`/`redhat:ansible_tower` products — plain community Ansible core's modern
  CPE identity did not resolve unambiguously by keyword search).
- **nginx** 0.1.27 / `igor_sysoev:nginx` (the only unambiguous nginx vendor:product pair
  the keyword search surfaced; NGINX's 2019 acquisition by F5 makes the *current* vendor
  attribution genuinely ambiguous without a targeted CPE-match-string lookup, which was out
  of scope for this pass).

One legitimate adversarial case surfaced during CPE verification and is called out
explicitly per test-design-policy P4/item 22 (a name that maps to a real product but under a
CPE `product` value that differs from the common display name): **Zoom** → confirmed CPE is
`zoom:meetings`, not `zoom:zoom` — the inventory-style name ("Zoom") and the CPE dictionary's
own product identifier ("meetings") diverge, exactly the kind of mismatch that can produce a
false non-match if a matcher requires literal product-string containment.

### Fictional products (15 rows, `UNIDENTIFIED`)

15 invented multi-word product+vendor names with no real-world referent. Each was still
independently checked against the live NVD CPE dictionary on 2026-08-29 (0 hits for every
one, see `golden300_cpe_results.tsv`) rather than asserting non-existence purely from
having invented the string — the task requires `ground_truth_source` to be non-blank and
meaningful on every row, fictional ones included.

### Real products confirmed absent from the CPE dictionary and the 10 OSV-backed registries (13 rows, `UNIDENTIFIED`)

**Revised 2026-08-29 (senior-reviewer review items 1/3/6) — was 15 rows; Blender and Rufus
moved out, see "Ground-truth correction: Blender and Rufus" below.**

Genuinely real, currently-shipping software, independently confirmed via live NVD CPE
keyword search to have **no** CPE dictionary entry as of 2026-08-29, and — by category
(desktop-only Windows/macOS utilities, never distributed via a language package manager) —
not members of any of the 10 OSV-backed registries either: Slack, OBS Studio, WinDirStat,
ExamDiff Pro, Bulk Rename Utility, WizTree, Directory Opus, ShareX, ClipboardFusion, Q-Dir,
XYplorer, Ditto, Process Hacker. This is a materially useful adversarial class: a pipeline
that guesses/hallucinates an identification for well-known software regardless of whether a
real CPE backs it would produce a false positive here, which is exactly what this bucket is
designed to catch.

**Important correction to the original claim (item 6):** "not members of any of the 10
[OSV-backed] registries" does **not** mean "not members of any of the app's 11 registries."
Job 168 actually found live Chocolatey catalog hits for 7 of these 13 (Slack, OBS Studio,
WinDirStat, WizTree, ShareX, ClipboardFusion, XYplorer) — they genuinely are listed in
Chocolatey. The original phrasing ("not distributed via any of the 10 supported package
registries") was simply wrong for these 7 rows, not just off-by-one in the registry count,
because at the time this note was written the existence of an 11th (Chocolatey) registry
hadn't been accounted for at all. See the next section for why `expected_outcome` stays
`UNIDENTIFIED` for these rows regardless.

### Chocolatey and the `UNIDENTIFIED` control bucket

**New section, 2026-08-29 (senior-reviewer review item 6).** Chocolatey
(`ChocolateyRegistryClient`) is real and supported, but it is structurally different from the
other 10 registries: it carries no CPE mapping, and it is not one of the 10 OSV-native
ecosystems `OsvSyncService` mirrors (`SUPPORTED_OSV_ECOSYSTEMS`, confirmed in code) — so a
Chocolatey match produces a bare `pkg:chocolatey/<id>@<version>` purl with **no path to any
vulnerability data at all**, CPE-based or OSV-based. This raises a real design question this
note previously left implicit: should a Chocolatey-only match count as a correct
identification for this benchmark's `UNIDENTIFIED` control rows?

**Decision (this engineer's judgment, per this task's brief): no — `expected_outcome` stays
`UNIDENTIFIED` for all 13 rows above, even the 7 that genuinely have a Chocolatey catalog
entry.** Rationale: this control bucket exists specifically to catch a pipeline that
overclaims identification for software it cannot actually source vulnerability data for
(see the bucket's original purpose statement above). A Chocolatey-only match is exactly that
failure mode wearing a different hat — it *looks* like a successful identification (status
`IDENTIFIED`, confidence 0.95) but delivers nothing the app's actual purpose (finding known
vulnerabilities) can use, since there is no CVE/GHSA feed keyed to `chocolatey` package names
and no CPE to match against NVD. Treating it as "correct" would make the control bucket blind
to precisely the risk it was built to catch. This is a defensible design call, not a
forced one — a reasonable counter-argument is that inventory-only use cases (asset tracking
without vulnerability lookup) might value a Chocolatey hit on its own — but nothing in this
project's stated purpose (CSV-driven **vulnerability** pre-screening, `docs/spec/README.md`)
supports scoring an identification with no vulnerability-data path as a success.

**Consequence for the false-positive count:** the 7 Chocolatey-routed hits on these rows
(Slack, OBS Studio, WinDirStat, WizTree, ShareX, ClipboardFusion, XYplorer) remain scored as
false positives — this is unchanged by the above decision, since the decision is "don't
credit Chocolatey-only matches as correct," which is exactly what `compute_golden_300_metrics.py`
already does today (`actual_status == "IDENTIFIED"` and `expected_outcome == "UNIDENTIFIED"`
→ false positive, independent of *which* registry produced the match). What changed is that 2
of the 9 originally-reported "chocolatey false positives" (Blender, Rufus) turned out to be
ground-truth errors, not app errors — see the next section and
`docs/spec/nfr-status-2026-08.md` §2 for the corrected count (7, not 9).

### Ground-truth correction: Blender and Rufus (2026-08-29, senior-reviewer review items 1-3)

Both rows were originally placed in the "real products confirmed absent" bucket above
(`expected_outcome=UNIDENTIFIED`) on the strength of a keyword search that came back "0
relevant results." That conclusion was wrong, for two compounding reasons:

1. **The query itself was over-narrowed.** The recorded query appended the vendor name to
   the product name — `"blender foundation"`, `"Rufus Pete Batard"` — rather than querying
   the bare product name. Both narrowed queries genuinely do return 0 hits; that part of the
   original check was accurate. But it was answering the wrong question — a human filling out
   a CSV row from a plausible-sounding vendor string is not the same test as "does this
   product have a CPE dictionary entry."
2. **The verification tool itself (`verify_nvd_cpe_candidates.py`) had a paging bug (item 1).**
   It queried with `resultsPerPage=15` and stopped collecting distinct vendor:product pairs
   once it had seen 8 of them. For a bare, broad query like `"blender"` (`totalResults=232`)
   or `"rufus"` (`totalResults=154`), the first 15 raw results are dominated by unrelated
   noise (`tweet-blender:tweet-blender`, a WordPress plugin; various `rufus_project:rufus`
   entries) that fills the 8-pair cap before the real entry is ever reached. So even re-running
   the *correctly broad* query with the *original, buggy* tool risked reproducing the same
   wrong "0 relevant results" conclusion.

Both bugs are fixed (item 1: `test-data/verify_nvd_cpe_candidates.py` now pages through
`totalResults` via `startIndex` and never caps the distinct-pair count; item 2, see the
recording-rule note below). Re-verified 2026-08-29 with the fixed tool against the bare
product name, then cross-confirmed with `cpeMatchString` (same rigor as the 14
disagreement rows in "Post-run CPE ambiguity findings" below):

| Product | Query | `totalResults` | Confirmed CPE | cpeMatchString confirmation |
|---|---|---|---|---|
| Blender | `blender` | 232 | `cpe:2.3:a:blender:blender` | 159 dictionary entries under this vendor:product (exact version 4.2.1 not itself a dictionary entry, but this app's CPE match keys on vendor:product, not the specific version being present — same convention already documented above for the 62-row CPE_DESKTOP segment) |
| Rufus | `rufus` | 154 | `cpe:2.3:a:akeo:rufus` | 91 dictionary entries under this vendor:product; exact version 4.5 IS present as its own entry. A second candidate, `rufus_project:rufus` (63 entries), was also checked and does **not** have a 4.5 entry — no ambiguity, `akeo:rufus` is the unambiguous match |

Both rows are corrected to `IDENTIFIED_CPE` (Blender: `blender`/`blender`; Rufus:
`akeo`/`rufus`). **Job 168's original output was correct all along**
(`cpe:2.3:a:blender:blender:4.2.1`, `cpe:2.3:a:akeo:rufus:4.5`) — this dataset's ground truth
was wrong, not the app. Both were counted as false positives in the first `nfr-status-2026-08.md`
write-up; `docs/spec/nfr-status-2026-08.md` §2 has been corrected accordingly (item 7).

#### `ground_truth_source` recording rule (item 2, applies dataset-wide going forward)

The Blender/Rufus error above was compounded by a `ground_truth_source` recording practice
that actively obscured it: after the broad query, a narrower follow-up query was run (adding
the vendor name), and **only the narrow query's URL was recorded** as `ground_truth_source`,
even though the narrow query was not what produced the informative result — it produced a
misleading `0 results`, which was then taken at face value without reference back to the
broad query's 232/154 hit counts. A reader auditing `ground_truth_source` after the fact would
see a URL that returns 0 results and have no way to know a much more informative broad query
had also been run and disagreed.

**Rule going forward: `ground_truth_source` must cite the query that actually produced the
evidence the row's `expected_outcome`/`expected_cpe_vendor`/`expected_cpe_product` is based
on — not a subsequent narrower query, even if the narrower query is the last one run before
filling in the CSV.** If multiple queries were run for a row, the source should say so and
link the one that resolved the question (per `cpe_source()`'s free-text `note` parameter in
`gen_golden_300.py` — see the corrected Blender/Rufus `add()` calls for the pattern: the note
explicitly states `totalResults=N` from the broad query, not just the final vendor:product
verdict).

**Correction (2026-08-29, senior-reviewer re-review item 3): the claim above ("this rule is
retroactively satisfied for every other row in this dataset") is retracted -- it does not hold.**
Two further problems surfaced on audit:

1. **`ground_truth_source` recorded a `resultsPerPage=15` (or otherwise narrow) query for rows
   that were actually re-verified with the item-1-fixed, full-pagination
   (`resultsPerPage=200`) tool.** This affected all 15 fictional rows and all 13 real-absent
   rows (28 rows total, `test-data/golden300_cpe_results.tsv`'s `resultsPerPage=200` re-run
   entries are the actual evidence for these rows, per "Verification coverage" item 4 above) --
   the CSV's recorded URL understated what was actually run. **Fixed in `gen_golden_300.py`**:
   both loops now pass `results_per_page=200` to `cpe_source()`, matching the tool that was
   actually executed.
2. **Rows that are not among those 28, plus the Blender/Rufus 2 rows already fixed, remain on
   the original `resultsPerPage=15` query and have not been re-run at full pagination**: the 62
   `CPE_DESKTOP` rows and the 8 job-167 regression rows. This is an honest reflection of what
   was actually executed for them (a single `resultsPerPage=15` keyword search, not the
   item-1-fixed tool), not an error to fix by rewriting their source URLs -- but it does mean
   the earlier "retroactively satisfied for every other row" claim was simply untrue for these
   70 rows, and is listed here explicitly instead of asserted away.
3. **The Slack row (`REAL_ABSENT`, `keywordSearch=slack%20desktop`) had a more serious version
   of the original Blender/Rufus problem**: its recorded query is narrow (`"slack desktop"`,
   not the bare product name), and unlike Everything/Ditto/Android Studio/OWASP ZAP elsewhere
   in this file (whose note text at least mentions an alternate query tried), Slack's note text
   said nothing about a broader query ever being run. Senior-reviewer independently re-checked
   both `cpeMatchString=cpe:2.3:a:slack:slack` (totalResults=0) and the broad
   `keywordSearch=slack` (also no desktop-Slack hit -- only `jenkins:slack`,
   `atlassian:jira_server_for_slack`, `slack-chat_project:slack-chat`, `slackware:slackware`,
   `slack:nebula`, `slack:wp_slacksync`). The ground truth itself (`UNIDENTIFIED`) is confirmed
   still correct; only the recorded evidence was imprecise. **Fixed in `gen_golden_300.py`**:
   the Slack row's `ground_truth_source` now carries this additional note
   (`SLACK_EXTRA_NOTE`).

## Holdout / corpus-contamination check (against `real-1000.csv`)

Per task requirement (>=150 non-overlapping rows), verified via
`test-data/check_golden_300.py` (exact `(product_name, version)` tuple comparison, the same
definition `test-design-policy.md` items B6/B10 already use elsewhere):

- **254 of 300 rows (85%) do not appear in `real-1000.csv` at all** (holdout requirement of
  >=150 satisfied with large margin).
- **46 rows exact-match `real-1000.csv` on `(product_name, version)`** — all 46 are registry
  packages where this file's live-fetched-latest version on 2026-08-29 happened to coincide
  with whichever version `real-1000.csv` recorded (i.e. that package hasn't released a new
  version since `real-1000.csv` was built). None of the 8 mandated job-167 regression rows,
  none of the 62+2 other/corrected CPE rows, and none of the 28 fictional+real-absent
  `UNIDENTIFIED` control rows (15+13, post Blender/Rufus correction) exact-match by version
  (their versions were deliberately chosen independently of what job 167 used).
- 241 of 300 rows share a `product_name` with some row in `real-1000.csv` (any version) —
  expected and not a contamination concern by itself, since `real-1000.csv` already covers
  ~932 distinct product names and many popular packages/products legitimately recur across
  independently-built test files; the tuple-level check above is the one that actually
  matters for "was this exact answer already tuned against."

## `usage_text` approach

Per test-design-policy P2/D16-D17: registry rows use a fixed per-ecosystem template (10
distinct strings, one per ecosystem, 20 occurrences each — same convention `real-400.csv`
established and a prior review accepted); every CPE/desktop and control row has a
hand-written, product-specific usage sentence (no round-robin pool). Every fictional row's
usage text is explicitly suffixed "(fictional product invented for this test)" so a reader
of the raw CSV is never misled into thinking it names a real tool.

## CSV hygiene (verified via `test-data/check_golden_300.py`)

- 300 data rows, 11 columns each, 0 rows with a wrong column count.
- 0 rows with a blank `ground_truth_source`.
- 0 exact duplicate `(product_name, version)` rows within the file itself.
- Header exact: `product_name,version,vendor,usage_text,install_url,expected_outcome,expected_ecosystem,expected_package_name,expected_cpe_vendor,expected_cpe_product,ground_truth_source`.
- Extra columns beyond the app's own 5 (`expected_outcome` etc.) are safe to upload as-is:
  `CsvParsingService.parse` (`backend/src/main/java/com/vulncheck/app/service/CsvParsingService.java:55`)
  reads only the 5 named columns via `ColumnMapping.identity()`; unknown extra columns are
  silently ignored by Commons CSV's header-based `CSVRecord.get(String)` lookup, not
  positionally misread.

## Post-run CPE ambiguity findings (2026-08-29, after job 168)

Job 168's actual output disagreed with this file's `expected_cpe_vendor`/`expected_cpe_product`
on 14 of the (then-66, pre-Blender/Rufus-correction) `IDENTIFIED_CPE` rows: 5 turned out to be
this file's own mistake (corrected below), 8 were confirmed genuine app false positives, and 1
(Kibana) was genuinely ambiguous. **Corrected 2026-08-29 (item 9): an earlier draft of this
note said "13," which undercounted by one relative to the 5+8+1 breakdown actually given below
— a plain addition error, not a hidden 14th row.** A second, textually-adjacent ambiguous row
(Ditto) is discussed in the same "genuinely ambiguous" bucket further below, but it is *not*
one of these 14 — Ditto's `expected_outcome` is `UNIDENTIFIED` (the ambiguity bucket it belongs
to is the `UNIDENTIFIED` control rows, not `IDENTIFIED_CPE`); grouping it together with Kibana
under one shared "genuinely ambiguous" heading in an earlier draft, without saying which
population each belonged to, is what produced the confusing appearance of a 15th/16th row here.
Per test-design-policy P1, disagreement with the app's own output is never grounds to just
adopt the app's answer as the new ground truth — but it also isn't grounds to assume the app
is wrong. Each of the 14 `IDENTIFIED_CPE` disagreements was independently re-verified via
`test-data/verify_cpe_match_string.py` (`cpeMatchString`, checking the full version range each
candidate vendor:product pair covers in the live NVD CPE dictionary, not just the single top
keyword-search hit `verify_nvd_cpe_candidates.py` had originally sampled from). Three outcomes
resulted:

**5 rows: this file's original ground truth was wrong, corrected in place.** In each case
the vendor identity behind a product changed at some point in its release history
(company acquisition/rebrand), the row's chosen *version* belongs to the post-change era,
and the original keyword search had picked the pre-change vendor tag because it happened to
surface first. Corrected `expected_cpe_vendor`/`expected_cpe_product` (see
`CPE_VERSION_ERA_CORRECTIONS` in `gen_golden_300.py` for the full evidence per row):

| Product | Version | Wrong (original) | Corrected | Evidence |
|---|---|---|---|---|
| Skype | 8.118.0.209 | `skype:skype` | `microsoft:skype` | `skype:skype` caps at v4.1.x (156 entries); `microsoft:skype` covers 7.x-8.x (8 entries incl. 8.35/8.59) |
| Docker Desktop | 4.33.0 | `docker:desktop` | `docker:docker_desktop` | `docker:desktop` caps ~2.1.x (187 entries); `docker:docker_desktop` continues through the 4.x series (143 entries) |
| Postman | 11.10.0 | `getpostman:postman` | `postman:postman` | `getpostman:postman` caps ~4.9.x (53 entries); `postman:postman` reaches the 10.x series (344 entries) |
| Symantec Endpoint Protection | 14.3.10148 | `symantec:endpoint_protection` | `broadcom:symantec_endpoint_protection` | `symantec:...` caps ~12.x (224 entries); `broadcom:...` covers 14.3.x (11 entries, incl. build 14.3.9210.6000, very close to this row's version) |
| PDF-XChange Editor | 10.2.1 | `tracker-software:pdf-xchange_editor` | `pdf-xchange:pdf-xchange_editor` | `tracker-software:...` sample capped ~6.0.x (71 entries); `pdf-xchange:...` includes build 10.3.0.386 (97 entries) |

**8 rows: this file's original ground truth was confirmed correct; job 168's actual CPE
match was a genuine false positive (wrong or stale vendor:product for the version given).**
Kept as scored false positives, not excluded:

| Product | App's (wrong) match | Why it's wrong |
|---|---|---|
| VirtualBox | `oracle:virtualbox` | Only 8 dictionary entries, capped ~v3.0 (early 2000s); `oracle:vm_virtualbox` (270 entries) is the continuously-used tag and the only one plausible for v7.0.14 |
| Zoom | `zoom:zoom` | 813 entries but with a completely different, date-encoded build-number scheme (e.g. `1.0.22331.0731`) inconsistent with Zoom Meetings' `5.x` versioning -- likely a different Zoom sub-product (e.g. a Rooms controller/appliance) sharing the vendor name |
| Audacity | `audacity:audacity` | Exactly 1 dictionary entry (v1.2.6, ~2006); `audacityteam:audacity` (67 entries) is the continuously-used tag |
| Adobe Acrobat Reader DC | `adobe:acrobat_reader` | Caps at legacy pre-"DC"-rebrand versioning (3.0-11.0, pre-2015); this row's v24.002.21005 belongs to the DC-era `adobe:acrobat_reader_dc` line (245 entries) |
| Node.js | `joyent:node.js` | Only 2 dictionary entries (v0.6.1/0.6.3, ~2012, Node's original corporate steward); `nodejs:node.js` (1693 entries) is the actively used tag since the Node.js Foundation/OpenJS era |
| RabbitMQ | `anynines:rabbitmq` | Only 7 entries, capped ~v2.1.2 (~2011); `pivotal_software:rabbitmq` (527 entries) is the tag actively used through modern 3.x releases |
| Tableau Desktop | `schneider_electric:tableau_desktop` | A different, unrelated real product (an industrial/SCADA tool from Schneider Electric that happens to share the exact product name) -- only 2 entries, versions 7.0/10.1.3, nothing resembling Salesforce Tableau's `2024.2` scheme; `tableau:tableau_desktop` (271 entries) is the actual BI tool |
| Greenshot | `greenshot:greenshot` | Exactly 1 dictionary entry (v1.2.10); `getgreenshot:greenshot` (80 entries, up to v1.3.178+) is the continuously-used tag |

**2 rows total, from two different populations, both genuinely ambiguous and excluded from
correctness/high-confidence scoring (still counted toward the identification-recall
numerator/denominator per their own bucket)** -- see `EXCLUDED_FROM_CORRECTNESS` in
`test-data/compute_golden_300_metrics.py`:

- **Kibana** 8.14.3 (one of the 14 `IDENTIFIED_CPE` disagreements above) -- `elastic:kibana`
  (app, 556 entries) vs `elasticsearch:kibana` (ours, 328 entries). Both are large, plausible
  dictionary entries reflecting the company's pre-/post-2016 rename from Elasticsearch BV to
  Elastic; the truncated version-range sample available from this check could not conclusively
  establish which one is current for v8.14.3. Scoring this row either way would misrepresent
  the app's actual accuracy on a question this task's re-verification pass could not itself
  resolve.
- **Ditto** 3.24.234.0 (`expected_outcome=UNIDENTIFIED`, one of the 13 "real products confirmed
  absent" control rows above -- NOT one of the 14 `IDENTIFIED_CPE` disagreements) -- a genuine,
  unresolvable name collision between two unrelated real products that happen to share the
  exact name "Ditto": the clipboard-manager utility this row was written to describe (real, but
  absent from the CPE dictionary and all 10 OSV-backed registries -- the original basis for
  putting it in the `UNIDENTIFIED` control bucket), and the Eclipse Foundation's real "Eclipse
  Ditto" IoT framework (`eclipse:ditto`, 30 dictionary entries), which is what the app actually
  matched. `product_name` alone cannot disambiguate
  these; this is a real limitation of choosing a single generic English word as a control
  probe without a vendor/context field the CPE matcher actually consults for disambiguation
  -- noted as a design lesson, not a scored error either direction.

### Correction-effect arithmetic (item 9, corrected 2026-08-29)

An earlier draft of this note claimed "is corrected before 87.7% (263/300) → after 90.94%
(271/298)," which does not reconcile with the stated cause (5 vendor-tag corrections + 2
exclusions): reverting 5 corrections from 271 gives 266, not 263, and the denominator/numerator
pairing across 87.7%/90.94% mixes n=300 and n=298 without isolating which effect did what.
**That 87.7%/263 figure cannot be independently re-derived after the fact** — the original,
not-yet-corrected CSV was overwritten in place by the fix and no snapshot of it was kept, so
this note cannot reproduce exactly how 263 was originally computed; it is retracted as
imprecise rather than repeated. What follows instead is the full chain, computed against data
still on hand (the current CSV + job 168's actual output), with each effect isolated on a
common denominator before/after it is applied:

| Step | n | correct | rate | What changed |
|---|---|---|---|---|
| 0. Baseline (no corrections, no exclusions, Blender/Rufus still mislabeled `UNIDENTIFIED`) | 300 | 266 | 88.67% | Starting point, reconstructed by reverting all three fixes below from the current, fully-corrected state |
| 1. + 5 vendor-tag corrections (Skype/Docker Desktop/Postman/Symantec EP/PDF-XChange Editor) | 300 | 271 | 90.33% | +5 correct: each of these 5 rows' `expected_cpe_vendor`/`expected_cpe_product` was wrong pre-acquisition/pre-rebrand tag; job 168's actual answer was right all along |
| 2. + 2 exclusions (Kibana, Ditto -- removed from the scoring population, not scored either way) | 298 | 271 | 90.94% | Numerator unchanged (both excluded rows were already counted incorrect); denominator shrinks by 2, which alone raises the rate from 90.33% to 90.94% with no accuracy change |
| 3. + 2 Blender/Rufus corrections (this task's items 1-3) | 298 | 273 | **91.61%** | +2 correct: both rows' `expected_outcome` was wrong (`UNIDENTIFIED` instead of `IDENTIFIED_CPE`); job 168's actual answer was right all along |

**Current, reported correctness rate: 273/298 = 91.61%** (`docs/spec/nfr-status-2026-08.md` §2
carries this forward). Step 1's effect (+5 correct, a genuine accuracy-of-ground-truth fix) and
step 2's effect (denominator shrink only, no accuracy change) are now shown separately per this
item's requirement, rather than folded into one combined before/after pair. It is recorded here
in full per test-design-policy P1/24 ("design note present and matching the file on every count
it claims") since the corrections happened after the CSV had already been used for job 168 --
the job's underlying identification/vulnerability data is completely unaffected
(`CsvParsingService` never reads the `expected_*` columns), only the answer key used to score
that job's output changed.

## Verification coverage (item 10, added 2026-08-29)

Not every one of the 300 rows carries the same weight of evidence -- some were checked once
with a keyword search, some were independently re-checked with a second, stronger method after
job 168 ran, and a few still rest on a single non-API-verified claim (the 200 registry rows'
live API hit). This section makes that explicit rather than letting a reader assume uniform
rigor across the file.

| Bucket | Rows | Verified by | Re-verified with a second, stronger method? |
|---|---|---|---|
| `IDENTIFIED_REGISTRY` (10 ecosystems) | 200 | Live registry API hit, one request per row (`golden300_registry_results.tsv`) | No -- a live 2xx registry response for the exact `(name, version)` is already a direct, unambiguous confirmation; there is no stronger check to apply |
| Job-167 regression, `IDENTIFIED_CPE` (Cisco IOS XE, PAN-OS, MikroTik RouterOS, Metasploit Framework) | 4 | NVD CPE keyword search | No -- job 168 disagreed (false negative, not a wrong-vendor mismatch), so `verify_cpe_match_string.py`'s "which vendor is right" check doesn't apply; the open question here is why the app didn't surface an existing `part=o`/`part=a` CPE, not whether the CPE itself exists |
| Job-167 regression, `UNIDENTIFIED` (Android Studio, OWASP ZAP, Unreal Engine, Windows Terminal) | 4 | NVD CPE keyword search, multiple phrasings tried; resolved via senior-reviewer live re-check (2026-08-29, re-review item 7) | **Yes** -- Unreal Engine: `cpe:2.3:a:epicgames:unreal_engine` totalResults=0, and the broad `unreal engine` keyword search totalResults=1 (only `americasarmy:proving_grounds`, an unrelated game, no entry for the engine itself); Windows Terminal: broad search totalResults=43, only `microsoft:windows_2000_terminal_services` and `windows_nt`-family entries, no `windows_terminal` entry; OWASP ZAP: broad `zap` keyword totalResults=62, only Jenkins-plugin CPEs (`jenkins:owasp_zap` etc.), no entry for the tool itself; Android Studio: already had 2 independent 0-hit phrasings recorded above (`android_studio`, "Google Android Studio IDE"). All 4 confirmed correctly `UNIDENTIFIED` -- the residual gap this table previously flagged for these 4 rows is closed |
| Other real desktop/CLI, `IDENTIFIED_CPE`, job 168 AGREED in the current, corrected CSV (item 5) | 53 | NVD CPE keyword search, then `verify_cpe_match_string_agreeing_rows.py` (`cpeMatchString`, confirms the vendor:product pair is a genuine non-fabricated dictionary entry) | **Yes (2026-08-29, item 5)** -- all 53 confirmed non-zero `totalResults`, ruling out fabrication on either side of the agreement. **Of these 53, 5 (Skype, Docker Desktop, Postman, Symantec Endpoint Protection, PDF-XChange Editor) only agree because this file's own ground truth was corrected (see "Post-run CPE ambiguity findings" below) -- before that correction they were part of the 14 originally-disagreeing rows counted in the next row of this table. They are not double-counted in the 300-row total below: the next row's count (9) already excludes them.** |
| Other real desktop/CLI, `IDENTIFIED_CPE`, job 168 still DISAGREES in the current, corrected CSV | 9 (8 confirmed-app-wrong + Kibana, excluded from correctness scoring) | NVD CPE keyword search, then `verify_cpe_match_string.py` (full version-range check) | **Yes** -- this is the "Post-run CPE ambiguity findings" section above. Historically 14 rows disagreed against the *pre-correction* ground truth (5 corrected + 8 confirmed-app-wrong + 1 Kibana); after the 5 corrections were applied those 5 rows moved into the AGREED-53 bucket above, leaving 9 still-disagreeing rows in the current CSV (8 confirmed-app-wrong, kept as scored false positives, + Kibana, excluded) |
| Blender, Rufus (`IDENTIFIED_CPE`, corrected) | 2 | NVD CPE keyword search (fixed tool, full pagination) | **Yes (2026-08-29, items 1/3)** -- cross-confirmed with `cpeMatchString` against the exact version, see "Ground-truth correction: Blender and Rufus" above |
| Fictional products (`UNIDENTIFIED`) | 15 | NVD CPE keyword search | **Yes (2026-08-29, item 4)** -- re-run with the item-1-fixed tool (full pagination, no 8-pair cap); all 15 still confirmed 0 hits |
| Real-absent products (`UNIDENTIFIED`), excl. Ditto | 12 | NVD CPE keyword search | **Yes (2026-08-29, item 4)** -- re-run with the fixed tool; all 12 still confirmed 0 hits |
| Ditto (`UNIDENTIFIED`, ambiguous, excluded) | 1 | NVD CPE keyword search | **Yes (2026-08-29, item 4)** -- re-run with the fixed tool, still 0 hits for the clipboard-manager sense; the ambiguity is with `eclipse:ditto`, a real but unrelated product, already discussed above |

**Rows column total check (corrected 2026-08-29, senior-reviewer re-review item 2): 200+4+4+53+9+2+15+12+1 = 300.**
An earlier draft of this table summed to 305 because the AGREED-53 row and the DISAGREED row
both counted the same 5 rows (Skype, Docker Desktop, Postman, Symantec Endpoint Protection,
PDF-XChange Editor) -- once as part of the pre-correction "14 disagreed" figure, again as part
of the post-correction "53 agreed" figure. The DISAGREED row above now reports 9 (the rows that
still disagree in the current, corrected CSV), which does not overlap with the 53 -- 53+9=62,
matching the 62-row "Other real desktop/CLI" `IDENTIFIED_CPE` segment exactly. The historical
"14" figure remains accurate and useful (it is what "Post-run CPE ambiguity findings" below
describes, as of the pre-correction state), it is simply not additive with the 53 for a
row-count total.

**Residual gaps -- both resolved (2026-08-29, senior-reviewer re-review item 7).** This table
previously flagged two open items here; neither remains open:
- The 4 job-167 `UNIDENTIFIED` regression rows (Android Studio, OWASP ZAP, Unreal Engine,
  Windows Terminal) were not re-run through the item-1-fixed full-pagination tool the way the
  fictional/real-absent control rows were. Closed: senior-reviewer independently live-checked
  all 4 (evidence transcribed into the table row above) and confirmed `UNIDENTIFIED` is correct
  for each.
- The 200 `IDENTIFIED_REGISTRY` rows have no independent second-method check. Closed as not
  applicable, not merely deferred: a 2xx response from the registry API for the exact
  `(name, version)` is already a direct, unambiguous confirmation, and there is no stronger
  verification method to apply to that kind of claim -- this was mis-flagged as an open gap
  rather than a settled non-issue in the earlier draft of this table.

## Review

**2026-08-29 revision (this submission):** senior-reviewer's first-pass review of this dataset
returned 11 required fixes (paging bug in the CPE verification tool; a misleading
`ground_truth_source` recording practice; 2 ground-truth errors, Blender and Rufus; the 30
`UNIDENTIFIED` control rows and the 53 previously-unverified agreeing `IDENTIFIED_CPE` rows
both re-checked with stronger methods; the Chocolatey registry omission and the resulting
false-positive recount; the identification-rate metric definition; an arithmetic
inconsistency in the correction-effect writeup; a verification-coverage section; and a full
recomputation of `docs/spec/nfr-status-2026-08.md` §2). All 11 are implemented above and in
`gen_golden_300.py` / `compute_golden_300_metrics.py` / `docs/spec/nfr-status-2026-08.md`.
The goal-2 "target not met" conclusion is unchanged by this revision (91.61% correctness /
67.11% strict high-confidence-correctness, both still well under 95%) — what changed is the
precision and defensibility of the supporting numbers, not the gate outcome.

**2026-08-29 second revision:** senior-reviewer's re-review of the above returned 7 further
REVISE items, all implemented: (1) a genuine aggregation bug in
`compute_golden_300_metrics.py` (the `EXCLUDED_FROM_CORRECTNESS` `continue` ran before the
identification-count accounting, so Kibana/Ditto never reached the recall numerator /
control-row false-positive count -- fixed, recall corrected 98.13%→98.51%
(263/268→264/268), control-row false-positive rate corrected 21.88%→25.00% (7/32→8/32),
propagated to `docs/spec/nfr-status-2026-08.md`); (2) the "Verification coverage" table's
Rows column summed to 305 instead of 300 due to double-counting 5 rows across the AGREED-53
and DISAGREED buckets -- fixed (see the table's total-check note above), and
`verify_cpe_match_string_agreeing_rows.py`'s docstring "13 rows DISAGREED" corrected to 14;
(3) the `ground_truth_source` recording rule's "retroactively satisfied for every other row"
claim was false -- retracted, with the 28 fictional/real-absent rows' recorded
`resultsPerPage` corrected to 200 (matching what was actually run) and the Slack row given
an additional senior-reviewer-verified evidence note (see "`ground_truth_source` recording
rule" above); (4) a new `docs/spec/known-limitations.md` entry documenting the
Chocolatey-only-match false-confidence risk; (5) `verify_cpe_match_string_agreeing_rows.py`
now persists its output to `test-data/golden300_cpe_matchstring_results.tsv` (re-run,
confirmed 0/53 fabricated); (6) a stale heading reference in `gen_golden_300.py`'s comments
fixed ("Ground-truth policy correction" → "Ground-truth correction"); (7) the two residual
gaps the "Verification coverage" table previously left open (job-167's 4 `UNIDENTIFIED`
regression rows not re-run at full pagination; the 200 registry rows' single-method
verification) are both closed -- see that section above. None of these 7 fixes change the
goal-2 conclusion: correctness rate 91.61% (273/298) and high-confidence correctness rate
67.11% (200/298) are both unaffected by the metrics-script fix (it only touches the
recall/control-row-false-positive metrics) and remain well under the 95% target.

**2026-08-29 third revision:** senior-reviewer's re-review of the second revision confirmed
all 7 items above were correctly reflected, but flagged 4 further items: (1) a
`known-limitations.md` regression where the Chocolatey-entry insertion had clobbered the
heading of the pre-existing sync-exclusion-control entry, merging two bullets into one; (2)
the Chocolatey entry's "7〜8件" range narrowed to the confirmed "7件" (the 8th control-row
false positive, Ditto, is an unrelated `cpe:2.3:a:eclipse:ditto` name-collision mismatch, not
a Chocolatey-sourced one); (3) `job168_results.csv` copied from `/tmp` into
`test-data/job168_results.csv` and `compute_golden_300_metrics.py`'s read path (and its
module docstring) updated to point at the persisted copy, re-run and confirmed unchanged
(recall 264/268 = 98.51%, control-row false-positive rate 8/32 = 25.00%, correctness rate
273/298 = 91.61%, strict high-confidence correctness 200/298 = 67.11%); (4) this review-status
line updated to record sign-off. All 4 implemented.

**2026-08-29 addendum (AI cost target fix, item 9):** confirmed the `llm-service/main.py`
`_count_web_searches` measurement bug (see `docs/spec/nfr-status-2026-08.md` §1, job-185
cost test) has zero effect on this dataset's goal-2 measurement. Two independent reasons:
(1) job 168 (which produced every number in this document) was run with an NVD-only key and
no Claude API key configured for its user — `docs/spec/nfr-status-2026-08.md`'s job-168
description states this explicitly ("NVDキーのみ・Claudeキー無し"), so llm-service's
`web_search_research`/`web_search_identify`/`disambiguate` endpoints were never invoked for
this job at all, meaning `_count_web_searches` never ran during golden-300 measurement,
buggy or otherwise. (2) Independently of (1), this dataset's own scope is Stage1/Tier1 only
("static precision, Stage1/Tier1 only, no AI" — see this document's Purpose section above),
i.e. registry/CPE-dictionary lookups with zero AI or web_search involvement even in a job
that *did* have a Claude key configured. Either fact alone rules out any interaction between
the two; both hold, and neither the recall/correctness/high-confidence-correctness figures
above nor the goal-2 "target not met" conclusion require any revision.

Reviewed-by: senior-reviewer (task originator) — **approved 2026-08-29.** This design note
and `golden-300.csv`, together with the fixes recorded in the second and third revisions
above, have passed the mandatory second-engineer/reviewer sign-off per test-design-policy.md
and are the goal-2 measurement of record.
