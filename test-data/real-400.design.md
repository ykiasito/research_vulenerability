# `real-400.csv` — Design Note

Generator: `test-data/gen_400.py` (deterministic, no randomness, no seed needed — fully
enumerated). Re-running the generator reproduces the CSV byte-identically.

## Purpose

A 400-row realistic test job for the vulnerability-lookup pipeline's AI (Tier2/Tier3)
identification/disambiguation path. Used for job id 34 (already completed; not touched by
this note or the 2026-08-25 fix described below). Composition is designed to exercise:
non-registry desktop/CLI software identification, registry/ecosystem package
identification across 10 ecosystems, and — as the primary adversarial class — name
collisions where the same real product is queried under two different display names.

## Row count and composition

- **Total: 400 rows.**
- **Non-registry (desktop/CLI software): 240 rows.** `vendor` is always populated for
  this segment.
- **Registry/ecosystem packages: 160 rows** — 10 ecosystems x 16 rows each. `vendor` is
  always empty for this segment (package registries generally don't carry a separate
  "vendor" field the way desktop software listings do; this is deliberate, not an
  accident of generation — see Field notes below).
- **Ratio: 240/160 (60% / 40%), non-registry / registry.**

### Per-ecosystem breakdown (registry segment, 160 rows)

| Ecosystem | Rows |
|---|---|
| npm registry | 16 |
| PyPI | 16 |
| NuGet | 16 |
| RubyGems | 16 |
| crates.io | 16 |
| Packagist | 16 |
| Hex (hex.pm) | 16 |
| pub.dev | 16 |
| Maven Central | 16 |
| Go module proxy | 16 |

## Distinct product coverage (the number that matters, not row count)

Row count alone overstates coverage because of two independent duplication mechanisms in
the non-registry segment (name-variance pairs, and a second older-version row for some
products). Both distinct-name and distinct-**family** counts (family = same real-world
product, collapsing name-variance pairs to one) are reported below, verified directly
against the generated file:

| Segment | Rows | Distinct names | Distinct families |
|---|---|---|---|
| Non-registry | 240 | 190 | 170 |
| Registry | 160 | 160 | 154 |
| **Total** | **400** | **350** | **324** |

So a 400-row file tests **324 distinct product families** — not 400, and not the
"~half" figure a naive "every product appears twice" assumption would suggest.

### Non-registry duplication mechanism, precisely

An earlier review pass characterized the entire non-registry segment as "100%
name-variance pairs, every desktop product appears in exactly 2 rows." That
characterization does not hold when checked against the actual file (verified via direct
`Counter` over `product_name` for rows where `vendor != ""`) — it conflated two distinct
duplication mechanisms and overstated the fraction affected. The real, verified picture:

- **20 explicit name-variance pairs** (40 rows, 20 families) — the same product queried
  under two different display strings, e.g. `Google Chrome` / `Chrome`. This is the
  deliberate adversarial class this segment exists to test. See the full list below.
- **50 primary products with a second, older-version row** (100 rows, 50 families) —
  same product name, same vendor, an earlier real release version. This is a version-
  recency probe, not a name-variance probe; it does not test name matching, it tests
  whether the pipeline still identifies a product correctly on an older version.
- **100 primary products with only a single row** (100 rows, 100 families) — no
  duplication of any kind.

Net effect: of 170 non-registry product families, 70 (41%) recur across exactly 2 rows
(via one of the two mechanisms above) and 100 (59%) appear exactly once. This is the
distinct-product-coverage effect the earlier review was gesturing at (240 rows ≠ 240
distinct products), but the precise mechanism and magnitude are as stated here, not "100%
name-variance." Per policy P6, this is stated explicitly rather than left for a reviewer
to discover by re-deriving it from the row data.

### Registry segment name-variance pairs

**6 explicit name-variance/collision pairs** (12 rows, 6 families) are woven into the
160 registry rows — see full list below. The other 148 registry rows are singleton
packages, one row each.

## Full list of the 26 name-variance pairs, with rationale

Each pair probes a different real-world reason the same product shows up under two
different strings in inventory/asset data. `family_key` is an internal grouping label,
not a CSV column.

### Non-registry (20 pairs, 40 rows)

| # | Name A | Name B | Rationale |
|---|---|---|---|
| 1 | Visual Studio Code | VS Code | Full product name vs. the abbreviation almost everyone actually types |
| 2 | 7-Zip | 7zip | Punctuation/spacing variant |
| 3 | Notepad++ | notepad-plus-plus | Symbol-bearing name vs. an ASCII/URL-safe spelled-out variant seen in some inventories |
| 4 | Microsoft Teams | Teams | Vendor-prefixed vs. bare name |
| 5 | Google Chrome | Chrome | Vendor-prefixed vs. bare name |
| 6 | Mozilla Firefox | Firefox | Vendor-prefixed vs. bare name |
| 7 | VMware Workstation Pro | VMware Workstation | Edition suffix ("Pro") dropped |
| 8 | Zoom | Zoom Client | Bare name vs. "Client"-suffixed variant |
| 9 | Slack | Slack desktop | Bare name vs. platform-suffixed variant |
| 10 | FileZilla | FileZilla Client | Bare name vs. "Client"-suffixed variant (note: FileZilla **Server** is a separate, distinct product also present in this file as a singleton — not part of this pair; a reviewer should confirm it isn't miscounted as a third pair member) |
| 11 | Microsoft PowerToys | PowerToys | Vendor-prefixed vs. bare name |
| 12 | Adobe Acrobat Reader DC | Acrobat Reader | Full branded name vs. shortened name with version suffix dropped |
| 13 | VirtualBox | Oracle VM VirtualBox | Bare name vs. full vendor-prefixed name |
| 14 | Microsoft Edge | Edge | Vendor-prefixed vs. bare name |
| 15 | Mozilla Thunderbird | Thunderbird | Vendor-prefixed vs. bare name |
| 16 | VLC media player | VLC | Full descriptive name vs. acronym |
| 17 | GIMP | GNU Image Manipulation Program | Acronym vs. expanded name |
| 18 | Docker Desktop | Docker for Windows | Current product name vs. a legacy/platform-specific historical name for effectively the same product |
| 19 | KeePass | KeePass Password Safe | Bare name vs. descriptive full name |
| 20 | WinRAR | Win RAR | Spacing variant |

### Registry (6 pairs, 12 rows)

| # | Ecosystem | Name A | Name B | Rationale |
|---|---|---|---|---|
| 21 | npm | angular | @angular/core | **Not a pure display-name variant** — `angular` (AngularJS 1.x, unscoped) and `@angular/core` (Angular 2+, scoped) are different major-version products from the same vendor lineage with different current maintenance status. Included deliberately as a generic-name/version-ambiguity collision probe, distinct in kind from the other 25 pairs. Flagged here per test-design-policy checklist item B10 so a reviewer doesn't miscount it as a simple rename. |
| 22 | PyPI | bs4 | beautifulsoup4 | Common short alias vs. canonical PyPI package name |
| 23 | NuGet | Newtonsoft.Json | Json.NET | NuGet package ID vs. the library's commonly used display/marketing name |
| 24 | crates.io | tokio | Tokio | Case-only variant (crates.io names are case-sensitive; this string would 404 as a real crate, but is realistic as a human-entered inventory value) |
| 25 | Maven Central | com.google.guava:guava | Guava | Full `groupId:artifactId` coordinate vs. bare display name |
| 26 | Go module proxy | gin | github.com/gin-gonic/gin | Bare package name vs. full Go module import path |

## Version-sourcing approach

All versions are real, released versions of the named product/package, chosen to be
plausible for the 2022–2023 era this file was authored against (not "latest" — several
are deliberately one or more releases behind current, and 50 non-registry products
additionally get an explicit older second version, see above). No version was
procedurally generated (no `random`/`randint`, no templating of version components).
Versions were hand-curated from known release history at authoring time, not fetched
live from each registry/vendor feed per row at generation time — this is a real-version
approach, not a registry-API-verified-at-generation-time approach; per test-design-policy
item A2, a reviewer sampling rows against live registry/release history is the
appropriate follow-up check before this file is reused for a new job.

Go module versions use the `v`-prefixed SemVer form (`v1.9.1`), Maven versions include
qualifiers where the real release has them (`32.0.1-jre`, `6.2.2.Final`), and several
non-registry versions use vendor-specific build-number schemes rather than plain
`x.y.z` (e.g. Skype `8.96.0.208`, Everything `1.4.1.1024`) — i.e. version format is not
uniform, matching real-world heterogeneity (test-design-policy item A3).

## `usage_text` approach (fixed 2026-08-25)

**Before the fix:** `usage_text` was drawn from a fixed pool of 25 canned strings,
round-robin cycled across all 400 rows regardless of which product a row was about. This
produced semantically wrong pairings (e.g. Mozilla Thunderbird, an email client, getting
"used for internal network diagnostics"; Chrome Remote Desktop getting "used as a backend
service dependency"). Since `usage_text` is sent directly into the Tier2/Tier3 LLM
identification prompt as "Usage / context text" (see `llm-service/main.py:187,369`), this
injected false context into the very field meant to help disambiguate the product.

**After the fix:** the round-robin pool is removed entirely. Every row's `usage_text` is
now one of:

1. **Hand-written, pair-specific text** for all 26 name-variance pairs (both members of a
   pair share the same text, since they denote the same real product) — this is the
   deliberate adversarial class, so it gets the most specific treatment.
2. **A per-product-category template** for the other 150 non-registry primary products —
   ~50 categories (e.g. `remote_desktop`, `antivirus`, `ide`, `db_client`,
   `hw_diagnostics`), each template true of every product mapped to it. Every primary
   product name is assigned a category by explicit mapping in `gen_400.py`
   (`NONREGISTRY_CATEGORY`), asserted complete at generation time so a reviewer can trace
   why any row has the text it has without re-deriving it (test-design-policy P5).
3. **A per-ecosystem template** for the 148 non-pair registry rows (e.g. "used as an npm
   package dependency in a Node.js/JavaScript project's build pipeline" for npm,
   "used as a Go module dependency imported in the codebase" for the Go module proxy) —
   true of essentially any package in that ecosystem.

No row's `usage_text` is empty in the current file — every row had enough real
information (a genuine product/package category) to support a category- or
pair-specific template. `usage_text` distinct-value count is 90 (out of 400 rows); the
most frequent single value occurs 16 times, always exactly matching one ecosystem's row
count (i.e. every occurrence is traceable to "this is what every package dependency in
this ecosystem gets," not an unexplained cluster).

## Field notes

- `install_url` is empty for every row (not populated in this design).
- `vendor` is populated for all 240 non-registry rows and empty for all 160 registry
  rows — this is the intended weak-signal-on-vendor design for the registry segment
  (registries don't carry a display vendor field the way desktop-software inventories
  do), not an accident of which code path populated which segment.
- No exact duplicate `(product_name, version)` rows exist in the file (verified via
  `cut -d, -f1,2 | sort | uniq -d`, empty output).

## Review

Reviewed-by: second-engineer / 2026-08-25 / PASS-with-notes

Only finding: this note previously stated `usage_text` distinct-value count as 87; the
actual file has 90 distinct values (corrected above). Everything else (byte-identical
regeneration, zero duplicate `(product_name,version)` rows, family/variance-pair counts,
composition ratios, and sampled semantic coherence of `usage_text`) verified correct.
