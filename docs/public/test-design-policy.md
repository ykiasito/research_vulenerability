# Test Design Policy — Test CSVs and Validation Jobs

Status: normative. Applies to every CSV under `test-data/` and every validation/accuracy job run against this pipeline.

## Why this exists

Every accuracy number this project has produced is only as good as the CSV that produced it. We have already burned a full stress-test cycle on a CSV whose version numbers were randomly generated (2026-08-24): 85% of items sat at a flat 0.50 confidence, which read as a matching-algorithm failure and was in fact *correct* behavior — the registry genuinely could not confirm versions that never existed. The re-run with real registry-fetched versions (job 31) produced 78% at 0.95 confidence. Same code, same pipeline, opposite conclusion. A bad test CSV does not produce a noisy measurement; it produces a **confidently wrong** one, and it costs paid API spend to produce.

The corollary is the reason this project has found real bugs at all: generic name collisions across registries, vendor-word query pollution, CPE version-duplicate noise, scoped npm packages, and name-variance handling were all surfaced by *deliberately adversarial, realistic* test data. Uniform "normal" rows have never found anything.

## Principles

**P1 — Every field must be real, or explicitly and visibly marked as a probe.**
`product_name`, `version`, and `vendor` must correspond to an actual shipped product and an actual released version. No `f"{randint(...)}.{randint(...)}.{randint(...)}"`, no version templating, no "plausible-looking" hand-invented versions. Source versions from the registry/release feed at generation time and record the source. If a row exists specifically to probe not-found behavior (a deliberately nonexistent version, a garbage name), it must be a **small, labeled, counted** subset — documented in the CSV's design note with its expected outcome — never the silent default for the whole file.

**P2 — `usage_text` is pipeline input, not filler.**
It feeds identification and disambiguation. A canned string cycled across unrelated products is worse than an empty field: it injects false context. If you cannot write usage text that is true of *that specific product*, leave it empty. Never round-robin a fixed pool of usage strings across a heterogeneous product list.

**P3 — Composition must mirror the real target corpus, and the ratio must be stated up front.**
Registry/ecosystem packages vs. non-registry desktop/CLI software, and the spread across npm / PyPI / RubyGems / Go / crates.io / Packagist / pub.dev / OS-level, are design decisions with a documented target ratio. The generator asserts the ratio; the reviewer verifies it against the actual file.

**P4 — Include adversarial cases on purpose, in known quantities.**
A useful CSV contains, deliberately and in counted amounts: name-variance pairs ("VS Code" / "Visual Studio Code"), generic/colliding names that exist in multiple registries, scoped and namespaced packages (`@scope/pkg`, `vendor/pkg`, `golang.org/x/...`), vendor words embedded in product names, versions with prefixes/suffixes (`v0.3.7`, `1.0.0-rc1`), and weak-signal rows (name only, no vendor, no usage text). Each adversarial class gets a documented expected outcome, so a wrong result is distinguishable from a hard case.

**P5 — A generator must be auditable: every repeat count must be explainable.**
For any product family in the output, a reviewer must be able to say *why* it appears exactly N times without reading the generator source. That means: no weighted-random sampling with replacement over a product pool, no product reachable via two code paths, no repeat that isn't the direct result of a declared rule ("each name-variance pair contributes exactly 2 rows"). Deterministic construction with a fixed seed, or explicit enumeration, beats random sampling every time. If the user has to ask "why does Chrome show up so often?", the design note should already have answered it.

**P6 — Distinct product coverage is the real coverage number, not row count.**
A 400-row CSV where every product appears twice tests 200 products, not 400. State both numbers. Do not let variance pairs silently halve coverage.

## Mandatory second-engineer review

No validation job result is trusted — and no paid job is launched — until a **second engineer, not the author**, has reviewed the test design and the generated CSV against the checklist below and recorded a sign-off. This is code review applied to test data, for the same reason: the author cannot see their own generation assumptions.

The author must supply, alongside the CSV:

- **A design note** (`test-data/<name>.design.md` or a header comment in the generator) stating: purpose, row count, distinct-product count, target composition ratio, the list of adversarial classes with expected counts and expected outcomes, the version-sourcing method, and the seed if randomness is used.
- **The generator script**, committed. A CSV produced by an uncommitted or ad-hoc script cannot be reviewed and cannot be re-run.

Reviewer records: `Reviewed-by: <engineer> / <date> / <PASS|PASS-with-notes|BLOCK>` plus findings. A BLOCK means the job does not run.

## Reviewer checklist

Run these against the CSV itself, not against the author's description of it. Field order is `product_name,version,vendor,usage_text,install_url`.

**A. Version realism (catches the 2026-08-24 class)**

1. Does the design note name a concrete version source (registry API, release feed, vendor download page) per segment? Reject "chosen to look realistic."
2. Sample 20 rows at random and verify each `version` against the real registry/release history. Any single fabricated version fails the file.
3. Scan for synthetic structure: unusually uniform component ranges, every version being 3-part `x.y.z` when the corpus contains Go (`v` prefix), Java, or OS packages, no pre-release/build metadata anywhere, suspiciously flat distribution of patch numbers.
4. Are versions vulnerability-relevant where the job's purpose requires it (i.e. old enough to have known CVEs), rather than uniformly "latest"?
5. Count of deliberately-nonexistent-version probe rows matches the documented count exactly.

**B. Frequency and duplication (catches the Chrome/Firefox class)**

6. Zero exact duplicate `(product_name, version)` rows:
   `tail -n +2 f.csv | cut -d, -f1,2 | sort | uniq -d`
7. Per-name frequency table produced and every count > 1 traced to a declared rule:
   `tail -n +2 f.csv | cut -d, -f1 | sort | uniq -c | sort -rn | head -40`
8. Per-**product-family** frequency (normalize variants: lowercase, strip vendor prefix, collapse "VS Code"/"Visual Studio Code", "Google Chrome"/"Chrome"). Any family exceeding the documented variance-pair count is a finding. This is the step that a raw per-name count will miss.
9. Distinct-name count and distinct-family count both reported and both consistent with the design note:
   `tail -n +2 f.csv | cut -d, -f1 | sort -u | wc -l`
10. Near-duplicate families that are actually *different products* (e.g. "Chrome" vs. "Chrome Remote Desktop", "Visual Studio" vs. "Visual Studio Code") are identified and confirmed intentional — they are legitimate collision probes but must not be miscounted as variance pairs, in either direction.
11. If the generator samples randomly: is it sampling **without** replacement, and is the seed fixed and recorded? Sampling with replacement over a weighted pool is an automatic BLOCK.

**C. Composition**

12. Registry vs. non-registry split computed from the file and within tolerance of the stated ratio.
13. Per-ecosystem counts computed and compared to the stated distribution; no ecosystem accidentally at zero or at 10x its intended share.
14. Distinct-product count (not row count) is stated and adequate for the job's purpose.
15. Vendor fill rate matches intent, and the rows where `vendor` is empty are the rows intended to be weak-signal probes — not an accident of which segment the generator happened to populate:
    `tail -n +2 f.csv | awk -F, '$3!=""' | wc -l`

**D. Field quality**

16. `usage_text`: count distinct values and their frequencies. A small pool of strings evenly distributed across many unrelated products is a BLOCK:
    `tail -n +2 f.csv | cut -d, -f4 | sort | uniq -c | sort -rn`
17. Sample 15 rows and read `product_name` + `usage_text` together. Every one must be semantically coherent (a Rust crate is not "installed on employee laptops"; an email client is not "used for network diagnostics").
18. CSV hygiene: header exact, correct column count on every row, no unescaped commas inside fields, encoding UTF-8, no stray BOM, `install_url` either valid or consistently empty.
19. Name spelling/casing matches how the product is actually written in the wild (this *is* the input under test — don't accidentally normalize away the variance you meant to test).

**E. Adversarial coverage**

20. Each declared adversarial class present, at the declared count, and locatable in the file by the reviewer.
21. Each adversarial row has a documented expected outcome, so post-run analysis can separate "pipeline is wrong" from "case is genuinely hard."
22. At least one scoped/namespaced package, one cross-registry generic name, one version with a non-plain format, and one name-only weak-signal row — unless the design note explicitly justifies their absence.

**F. Process**

23. Generator script committed and re-runnable; reviewer re-runs it and confirms it reproduces the CSV (byte-identical, or seed-identical).
24. Design note present and matching the file on every count it claims.
25. Cost/scale sanity: row count justified against the job's purpose and its API spend; results-set and rate-limit exposure considered for the run size.
26. Sign-off recorded before the job is launched.

## Failure log

Keep this list current; each entry is why a checklist item exists.

- **2026-08-24 — random version numbers.** 1,000-row stress CSV used `randint`-generated versions. 85% flat 0.50 confidence misread as a matching bug; job 31 with real versions gave 78% at 0.95. → Items A1–A5.
- **2026-08-25 — `real-400.csv`.** (a) `usage_text` was a 25-string pool cycled 16x each across unrelated products, injecting false context into an LLM-consumed field. (b) The entire 240-row non-registry segment was name-variance pairs — every desktop product exactly 2x — so "Chrome/Firefox recur oddly often" was a salience effect, not a sampling bug, but effective distinct-product coverage was half the row count and the design note did not say so. → Items B7–B9, C14, D16–D17, P6.
- **2026-08-26 — jobs 35→36→37, aggregate-count comparison.** Two consecutive rounds of fixes were checked only against the aggregate IDENTIFIED/UNIDENTIFIED count from the next 400-item run, which let real per-item regressions through undetected on both rounds (round 2's target_sw-aware fix silently broke Pillow/Rails/React/Sidekiq/TypeScript/Sophos Home while the aggregate count barely moved). This is a distinct failure mode from anything above — it isn't about the CSV's own design, it's about *how the result was compared* — and is addressed separately by a permanent per-item JUnit regression gate rather than another CSV-design rule: see `docs/public/stage1-golden-benchmark.md`.
