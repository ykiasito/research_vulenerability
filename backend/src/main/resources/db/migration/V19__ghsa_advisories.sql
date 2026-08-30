-- V19__ghsa_advisories.sql
-- Local mirror of GitHub Security Advisories (github-reviewed only, see
-- docs/spec/ghsa-mirror-plan.md §0(d)/§3 for the full design rationale). Six tables, mirroring the
-- cve_org_* pattern (V8) but shaped around GHSA's fixed ecosystem taxonomy and OSV-schema version
-- ranges rather than CVE.org's free-text vendor/product fields. Both the baseline (git tarball) and
-- delta (REST change-detection + raw.githubusercontent.com per-document fetch) sync paths funnel
-- through the SAME parser (plan §3-1 decision A) and write through the same shared upsert, so no
-- ingest-path-specific columns exist here.

-- One row per GHSA-reviewed advisory. raw_json is kept for re-derivation/debugging only — the
-- find()-time query path (GhsaVulnerabilitySource) never parses it.
CREATE TABLE ghsa_advisories (
    ghsa_id         VARCHAR(20) PRIMARY KEY,   -- e.g. GHSA-35jh-r3h4-6jhm
    cve_id          VARCHAR(30),               -- alias; some GHSA-reviewed advisories have no CVE
    summary         TEXT,
    details         TEXT,
    severity        VARCHAR(20),
    cvss_score      NUMERIC,
    withdrawn_at    TIMESTAMPTZ,               -- NOT NULL = withdrawn; excluded from find() (plan §6)
    published_at    TIMESTAMPTZ,               -- also used to derive the delta raw.githubusercontent.com path (plan §3-1)
    updated_at      TIMESTAMPTZ NOT NULL,      -- delta sync cursor source (GHSA's own modified/updated_at)
    html_url        TEXT,
    raw_json        TEXT NOT NULL,             -- re-derivation/debugging only
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ghsa_advisories_updated_at ON ghsa_advisories (updated_at);

-- One row per (advisory, ecosystem, package) triple.
-- package_name_normalized: plan §3-1 (D) — per-ecosystem normalization (PyPI: PEP 503, NuGet/Maven/
-- everything else: lowercase, npm: lowercase) applied identically at ingest time (here) and at
-- query time (GhsaVulnerabilitySource#find) via the same shared normalizer. package_name is the raw
-- text, kept for display/debugging only.
CREATE TABLE ghsa_affected_packages (
    id                       BIGSERIAL PRIMARY KEY,
    ghsa_id                  VARCHAR(20) NOT NULL REFERENCES ghsa_advisories(ghsa_id) ON DELETE CASCADE,
    ecosystem                VARCHAR(30) NOT NULL,   -- this app's internal ecosystem key (npm/pypi/maven/...)
    package_name             TEXT NOT NULL,          -- raw text (display)
    package_name_normalized  TEXT NOT NULL,          -- normalized (lookup/dedup)
    UNIQUE (ghsa_id, ecosystem, package_name_normalized)
);
CREATE INDEX idx_ghsa_affected_packages_lookup ON ghsa_affected_packages (ecosystem, package_name_normalized);
CREATE INDEX idx_ghsa_affected_packages_advisory ON ghsa_affected_packages (ghsa_id);

-- OSV's affected[].versions[] — an exact, range-independent enumeration of individually-known-
-- affected versions. find() must check this table for exact-match independently of
-- ghsa_affected_ranges' range evaluation — a range can be unevaluable (GIT type, unparseable
-- version, fail-closed per plan §3-1 (B)) while an exact-version hit here still counts.
CREATE TABLE ghsa_affected_versions (
    affected_package_id  BIGINT NOT NULL REFERENCES ghsa_affected_packages(id) ON DELETE CASCADE,
    version               TEXT NOT NULL,
    PRIMARY KEY (affected_package_id, version)
);
CREATE INDEX idx_ghsa_affected_versions_package ON ghsa_affected_versions (affected_package_id);

-- One row per independent vulnerable-version range an affected package has (a package can have
-- several disjoint ranges — e.g. "vulnerable in 2.x, fixed in 2.5, reintroduced+refixed in 3.x" —
-- plan §3-1 (C) event-pairing: an `introduced` event opens a range, the next `fixed`/`last_affected`
-- event closes it; `limit` events are ignored).
-- range_type: OSV's ranges[].type verbatim ('SEMVER'|'ECOSYSTEM'|'GIT'). find() must skip 'GIT'
-- ranges entirely (plan §3-1 (B)) — a commit SHA fed through VersionUtils.compare would just be a
-- meaningless lexicographic comparison.
-- introduced_version: NULL means "vulnerable from the very first version" (OSV's introduced:"0" is
-- normalized to NULL here).
-- fixed_version: '<' (exclusive upper bound, OSV's `fixed` event).
-- last_affected_version: '<=' (inclusive upper bound, OSV's `last_affected` event) — kept as a
-- SEPARATE column from fixed_version (not collapsed into one), mirroring
-- CveOrgVulnerabilitySource#isVersionAffected's lessThan/lessThanOrEqual split (plan §1-4): folding
-- both into a single column would misclassify a version exactly equal to a last_affected bound as
-- "safe".
CREATE TABLE ghsa_affected_ranges (
    id                     BIGSERIAL PRIMARY KEY,
    affected_package_id    BIGINT NOT NULL REFERENCES ghsa_affected_packages(id) ON DELETE CASCADE,
    range_type             VARCHAR(16) NOT NULL,
    introduced_version     TEXT,
    fixed_version          TEXT,
    last_affected_version  TEXT,
    CHECK (fixed_version IS NULL OR last_affected_version IS NULL)
);
CREATE INDEX idx_ghsa_affected_ranges_package ON ghsa_affected_ranges (affected_package_id);

-- Single-row sync progress/cursor, same pattern as cve_org_sync_state (V8).
-- sync_in_progress: baseline/delta mutual-exclusion flag (plan §6-2).
-- baseline_commit_sha: the commit SHA the baseline tarball resolved to, cross-checked against
-- GET /repos/github/advisory-database/commits/main (plan §6 — tarball downloads lose git's signed-
-- commit verification chain, so this is a partial substitute, not equivalent proof).
-- last_sync_error: most recent failure reason, surfaced on /admin/ghsa (plan §9-0).
CREATE TABLE ghsa_sync_state (
    id                    SMALLINT PRIMARY KEY DEFAULT 1,
    baseline_loaded       BOOLEAN NOT NULL DEFAULT false,
    baseline_commit_sha   TEXT,
    sync_in_progress      BOOLEAN NOT NULL DEFAULT false,
    last_cursor           TIMESTAMPTZ,   -- max processed ghsa_advisories.updated_at (delta's `modified` filter floor)
    last_synced_at        TIMESTAMPTZ,
    last_sync_error       TEXT,
    CHECK (id = 1)
);
INSERT INTO ghsa_sync_state (id) VALUES (1);

-- Dead-letter ledger for the "poison pill" escape hatch (plan §6-1): N consecutive processing
-- failures for the same ghsa_id skip it (with a WARN log and a row here) rather than permanently
-- wedging delta sync's cursor. No FK to ghsa_advisories — a document that fails to parse at all may
-- never have gotten a row there in the first place.
CREATE TABLE ghsa_sync_failures (
    ghsa_id               VARCHAR(20) PRIMARY KEY,
    consecutive_failures  INT NOT NULL DEFAULT 0,
    last_error            TEXT,
    last_attempted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dead_lettered_at      TIMESTAMPTZ
);
