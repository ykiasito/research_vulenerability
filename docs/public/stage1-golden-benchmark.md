# Stage1 Golden Benchmark — Per-Item Regression Gate

Status: normative for `Stage1IdentificationService` changes.

## Why this exists

Three rounds of ad-hoc 400-item CSV accuracy validation (jobs 35 → 36 → 37, see
`docs/public/test-design-policy.md` for the CSV-design side of that process) found real bugs, but
each round's *fixes* were only ever checked against the **aggregate** IDENTIFIED/UNIDENTIFIED
count from the next run. That let two full rounds of real regressions through undetected: round 2's
`target_sw`-aware ranking/gate fixed several bugs but silently broke several previously-correct
flagship matches (Pillow, Rails, React, Sidekiq, TypeScript, Sophos Home) and introduced new false
positives (Slack→wrong crates.io package, Redis Desktop Manager→wrong unrelated product) — none of
which an aggregate count could ever surface, since the total IDENTIFIED count barely moved while the
*specific* items that were IDENTIFIED changed underneath it.

This benchmark is the fix for that class of gap: a set of specific, adjudicated
`(product, expected outcome)` pairs, asserted individually, that runs as part of the normal `mvn
test` suite. A future change that regresses even one of these items fails the build — it doesn't
wait for the next multi-hundred-item validation round and a human eyeballing two aggregate numbers.

## What it is

`backend/src/test/java/com/vulncheck/app/service/Stage1GoldenBenchmarkTest.java`, a JUnit 5
`@ParameterizedTest` fed by `backend/src/test/resources/stage1-golden-benchmark.csv`. Each case in
the CSV:

- replays the exact real CPE-dictionary row(s) (and, where relevant, registry match) involved in
  that item's adjudication, as Mockito stubs — no live DB/network, consistent with every other test
  in `com.vulncheck.app.service` — against `Stage1IdentificationService#identify` directly, not a
  full job;
- asserts a specific expected outcome: `IDENTIFIED_WITH_CPE` (with the expected CPE
  vendor/product), `IDENTIFIED_NO_CPE` (registry-only, correctly no CPE — e.g. `junit:junit`, where
  NVD genuinely has no generic entry, only `junit4`/`junit5`), or `UNIDENTIFIED` (confirmed live
  against the real dictionary that no correct CPE exists at all).

The CSV columns:

| Column | Meaning |
|---|---|
| `case_id` | Groups multiple rows into one test case (one row per competing mocked dictionary candidate). |
| `product_name`, `vendor` | The CSV item fields being identified. |
| `registry_ecosystem`, `registry_package_name`, `registry_exact_version_confirmed` | The registry match to stub, if any (blank = no registry match). |
| `mock_cpe_string` | A real CPE 2.3 string from the live NVD dictionary (verified via `docker exec ... psql` against the running `cpe_dictionary` table at the time the case was added). Vendor/product are derived from this via `CpeUtils.parseVendorProduct` — the same code path production ingestion uses — not a separately hand-maintained column. Blank = this case has no dictionary candidate at all. |
| `mock_product` | Optional (round 4 addition); blank/absent = derive `product` from `mock_cpe_string` as above (every pre-round-4 row). When set, overrides just the derived `product` with a literal value — the only way to encode "this dictionary row's stored `product` column doesn't match what the CPE string itself parses to", e.g. the pre-backfill corrupted `ktat` row in `http_crates` (real stored `product` was literally `http\` — see the `V13__backfill_corrupted_cpe_vendor_product` migration). |
| `mock_cpe_title` | Optional; blank is valid (many real rows have none). |
| `mock_target_sw` | Semicolon-separated `target_sw` values, mirroring `CpeDictionaryEntry#getTargetSwValues`. Blank = no signal (as for a name-variant-derived candidate). |
| `expected_outcome` | `IDENTIFIED_WITH_CPE` \| `IDENTIFIED_NO_CPE` \| `UNIDENTIFIED`. |
| `expected_ecosystem`, `expected_cpe_vendor`, `expected_cpe_product` | Asserted only when non-blank and relevant to the outcome. |
| `notes` | Free text — which round/regression this case guards. |

The benchmark deliberately never exercises an AI disambiguation call (see the class-level javadoc
and `commonStubs()`): every real run in this environment has no Claude API key configured, and the
user has confirmed (2026-08-26) that the static-only (no-AI) pipeline is the quality bar to keep
validating against. A scenario that only resolves correctly *with* an AI call does not belong in
this benchmark.

## How to extend it

The common case — "a future validation round adjudicated one more product/outcome pair" — needs
**no new Java code**. Add a `case_id` group to `stage1-golden-benchmark.csv`:

1. Confirm the real dictionary row(s) live: `docker exec research_vulenerability-postgres-1 psql -U
   vulncheck -d vulncheck -c "SELECT cpe_string, title FROM cpe_dictionary WHERE vendor='...' AND
   product='...'"`. Never hand-invent a CPE string — every case in this file must trace to a real
   row, the same discipline `test-design-policy.md` requires of the CSV validation rounds this
   benchmark was built to backstop.
2. If the adjudication says "no correct CPE exists," confirm that negative directly too (query the
   dictionary for plausible vendor/product spellings and record that nothing matches) before
   encoding `UNIDENTIFIED` or `IDENTIFIED_NO_CPE` as the expected outcome — an unconfirmed
   `UNIDENTIFIED` expectation is exactly the "aggregate count moved, nobody checked why" failure
   mode this benchmark exists to prevent.
3. Add one CSV row per competing candidate under a new, unique `case_id`; repeat the
   `expected_*`/registry columns identically on every row of the group (the loader reads them from
   the group's first row, but keeping them consistent avoids a confusing diff later).
4. Run `mvn -Dtest=Stage1GoldenBenchmarkTest test` and confirm the new case passes for the *reason*
   you expect (check the `Stage1 identify item ...` INFO log line for that product name), not just
   that the assertion happens to pass.

Only write new Java code in `Stage1GoldenBenchmarkTest.java` for a scenario the CSV schema can't
express (e.g. asserting on `versionConfirmed`, or a case that genuinely needs an AI disambiguation
stub) — and prefer adding a narrower, purpose-built `@Test` in
`Stage1IdentificationServiceTest.java` instead when the mechanism under test is really about one
specific code path (e.g. `explainsQuery`'s alignment logic) rather than an end-to-end adjudicated
outcome.

## Known limitations — not bugs, don't re-"fix" these

Two real, adjudicated-correct answers are currently unreachable by this service's own
containment/similarity-threshold logic, for two different mechanical reasons. Both are locked in as
explicit `UNIDENTIFIED`-expected golden cases (`docker_for_windows`, `realvnc_viewer`) specifically
so a future round doesn't waste time rediscovering either as if it were a new bug:

- **`docker:desktop`** (the correct answer for an item literally named "Docker for Windows"): the
  pg_trgm product-similarity score for this exact query text falls below the 0.3 acceptance
  threshold — measured live, `similarity('docker_desktop','Docker for Windows')` = 0.269 — so the
  candidate never even enters the ranked pool for that query. (A *different* query text, "Docker
  Desktop", scores well above threshold and resolves correctly — see the pre-existing
  `docker_desktop` case above.)
- **`realvnc:vnc_viewer`** (the correct answer for "RealVNC Viewer"): reachable by similarity
  (0.5625, comfortably above threshold), but rejected by `explainsQuery`'s token-alignment
  containment check — the query's single token `realvnc` doesn't decompose into the candidate
  product slug's `vnc`+`viewer` tokens the way `alignPrefix`'s concatenation logic requires (it only
  handles one side's token being a literal prefix/suffix fragment of the other, not an unrelated
  compound-word split like `realvnc` → `vnc`).

Both are real gaps in the matching logic, not correctness bugs — nothing about them attaches a
*wrong* CPE, they just leave a real product `UNIDENTIFIED`. Widening either fix is legitimate future
work, but it is out of scope for round 4 and deliberately not attempted here.

## Current coverage

Seeded 2026-08-26 from every item named in the round-2/round-3 senior review writeups with a stated
adjudicated outcome (round 3, job 37 root-cause fixes): Pillow, Rails, React, Sidekiq, TypeScript
(round-3 ranking regressions), puma (round-2 win, must not regress), the crates.io `http` package
(escaped-colon CPE parsing), Slack (round-2 win), Redis Desktop Manager, Sophos Home, `junit`
(Maven), npm `commander`, Windows Terminal, Android Studio, Chrome Remote Desktop, Unity Hub, AVG
AntiVirus Free, Zoom, Docker Desktop, and Process Monitor. This is the round-3 subset, not the full
~120-item history across jobs 35-37 — future rounds should keep appending to it rather than
repeating the ad-hoc-CSV-plus-eyeball-comparison mistake this benchmark exists to end.

Round 4 (2026-08-26, senior review of job 38) added: a full 5-candidate rewrite of `http_crates`
(previously a single-mock-CPE case that couldn't actually reproduce either bug it claimed to guard —
see the CSV's own notes for the real tie order and target_sw values now encoded), `slack_jenkins_cpe`
(renamed from the old bare `slack` case_id, since it only ever covered the Jenkins-plugin-CPE half of
the real Slack bug), `slack_registry_only`/`bs4_registry_only`/`twig_registry_only` (the new REVISE
item 3 weak-registry-match static rejection rule and its negative controls), `docker_for_windows`/
`realvnc_viewer` (the known-limitations lock-ins above), and `zoom_client`/`express_npm` (job 38
ranking improvements that weren't yet guarded anywhere).
