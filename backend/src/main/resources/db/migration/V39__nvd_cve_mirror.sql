-- V39__nvd_cve_mirror.sql
-- Closed-mode backlog item 202 (§4-2 of docs/spec/closed-mode-plan.md): local mirror of the NVD
-- CVE API (services.nvd.nist.gov/rest/json/cves/2.0), analogous to V25's OSV mirror and the
-- existing cpe_dictionary mirror (V1/V31) but for CVE records + their CPE applicability ranges.
-- Off by default at the application layer (app.nvd-cve-backfill.enabled=false) -- this migration
-- only creates empty tables, it does not itself pull any data.
--
-- Four tables, two concerns:
--   1. Sync progress/resumability: nvd_cve_sync_state (single row, mirrors the baseline-complete/
--      delta-cursor shape of osv_sync_state) + nvd_cve_sync_chunk (one row per date-window chunk,
--      resumable down to the individual NVD API page via next_start_index -- see
--      NvdCveSyncService's class javadoc for why chunking exists at all: process-restart survival,
--      EC2 scheduled-uptime compatibility, NVD's 120-day lastMod range cap, and startIndex
--      instability against a moving dataset).
--   2. The mirrored data itself: nvd_cve_records (~320k rows) + nvd_cve_cpe_match (~10-15M rows,
--      one row per cpeMatch entry NVD reports across every CVE's configurations[].nodes[]).
--
-- raw_json is deliberately NOT stored on nvd_cve_records, following V25's OSV mirror precedent
-- (not V8's cve_org.sql, which does keep raw_json) -- at ~320k CVE records the multi-GB cost of
-- keeping the full response body isn't worth it against this app's 15GB DB cap, and nothing here
-- needs raw-document re-derivation the way the CVE.org mirror's own debugging workflow did.

-- Single-row sync-state tracker, same CHECK(id=1) singleton shape as osv_sync_state/ghsa_sync_state.
CREATE TABLE nvd_cve_sync_state (
    id                     SMALLINT PRIMARY KEY DEFAULT 1,
    baseline_completed     BOOLEAN NOT NULL DEFAULT false,
    baseline_started_at    TIMESTAMPTZ,
    -- High-water mark for the delta sync's own window (see NvdCveSyncService#runDeltaTick) -- only
    -- meaningful once baseline_completed is true. NULL until the first delta tick ever runs.
    last_delta_synced_at   TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (id = 1)
);
INSERT INTO nvd_cve_sync_state (id) VALUES (1);

-- One row per lastModified date-window chunk. Rows are seeded once, in full, the first time the
-- backfill runs (an 84-ish-row bulk insert covering [1999-01-01, now) in 120-day windows -- NVD's
-- documented lastModStartDate/lastModEndDate max range) -- see
-- NvdCveSyncService#ensureChunksSeeded. A chunk whose first page reports more results than the
-- adaptive-split threshold gets superseded by two new PENDING child chunks covering its two
-- date-range halves (also inserted here) rather than being deleted -- the original row is marked
-- COMPLETED once its own first page has been ingested and its children created, so "COMPLETED"
-- means "this row needs no further attention", not strictly "this window was paged through in
-- full" for a chunk that got split.
CREATE TABLE nvd_cve_sync_chunk (
    id                BIGSERIAL PRIMARY KEY,
    window_start      TIMESTAMPTZ NOT NULL,
    window_end        TIMESTAMPTZ NOT NULL,
    -- PENDING / IN_PROGRESS / FAILED / COMPLETED (see NvdCveSyncChunkStatus). FAILED is not a
    -- terminal give-up state -- it just records that the chunk's most recent page attempt errored
    -- (see last_error) while staying eligible for the next tick's retry, same as PENDING/
    -- IN_PROGRESS. Only COMPLETED is excluded from chunk selection.
    status            VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    -- Resume point *within* this window's own NVD pagination -- committed after every single page,
    -- so a mid-run crash/restart loses at most one page (2,000 records) of progress, not the whole
    -- chunk. See docs/spec/closed-mode-plan.md §4-2-4 for why chunk-level resumability alone (no
    -- next_start_index) was judged too coarse.
    next_start_index  INT NOT NULL DEFAULT 0,
    total_results     INT,
    upserted_count    INT NOT NULL DEFAULT 0,
    -- Counted per fetch *attempt*, not per success -- see NvdCveBackfillScheduledRunner/
    -- NvdCveSyncService's run-budget javadoc for why a 503-retry loop must consume budget the same
    -- as a successful page, or a single misbehaving chunk could starve every other chunk's progress
    -- for the rest of the run.
    attempt_count     INT NOT NULL DEFAULT 0,
    -- Sanitized only: HTTP status code + exception class name. Exception messages are deliberately
    -- excluded entirely (not truncated, not included at all) -- several RestClientException
    -- subclasses embed the request URL in getMessage(), and this column must never carry that,
    -- the raw API response body, or the request URL/query string -- see NvdCveSyncService's fetch
    -- error handling for why (this repo has an actual incident history of a real credential ending
    -- up in a persisted column meant for something else; a future keyed run must not repeat that
    -- via this column carrying an apiKey-bearing URL or header dump).
    last_error        TEXT,
    started_at        TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    UNIQUE (window_start, window_end)
);
CREATE INDEX idx_nvd_cve_sync_chunk_status_window ON nvd_cve_sync_chunk (status, window_start);

-- One row per CVE record. Description is the single English-language description NVD returns
-- (descriptions[] filtered to lang=en, same convention as NvdVulnerabilitySource's own
-- extractEnglishDescription). severity/cvss_score are the same v3.1 > v3.0 > v2 baseSeverity/
-- baseScore fallback chain NvdVulnerabilitySource already uses for its live-query findings, so a
-- future NvdVulnerabilitySource rewritten to read this table produces the same finding shape it
-- does today.
CREATE TABLE nvd_cve_records (
    cve_id             VARCHAR(30) PRIMARY KEY,
    description        TEXT,
    severity           VARCHAR(20),
    cvss_score         NUMERIC,
    published_at       TIMESTAMPTZ,
    last_modified_at   TIMESTAMPTZ NOT NULL,
    last_synced_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Backs the delta-sync window query (NvdCveSyncService#runDeltaTick reads CVEs whose
-- last_modified_at moved) and any future consumer that wants "recently changed" CVEs.
CREATE INDEX idx_nvd_cve_records_last_modified_at ON nvd_cve_records (last_modified_at);

-- One row per cpeMatch entry (vulnerabilities[].cve.configurations[].nodes[].cpeMatch[]) across
-- every mirrored CVE -- ~10-15M rows estimated (§4-2-6). This is what a future mirror-backed
-- NvdVulnerabilitySource rewrite (out of scope for this migration -- see backlog item 202's
-- A/B-verification gate) would query to reproduce NVD's own server-side CPE applicability
-- resolution locally: does any row for this (vendor, product) have a version range that contains
-- the item's installed version. vendor/product are parsed out of the cpeMatch's own criteria
-- string (CpeUtils.parseVendorProduct) purely so this table can be indexed and queried the same
-- way cpe_dictionary already is -- criteria itself is also kept verbatim (a single ~60-byte CPE
-- 2.3 string, not the full API response) so any parsing decision made here can be re-derived later
-- without re-fetching from NVD.
CREATE TABLE nvd_cve_cpe_match (
    id                        BIGSERIAL PRIMARY KEY,
    cve_id                    VARCHAR(30) NOT NULL REFERENCES nvd_cve_records (cve_id) ON DELETE CASCADE,
    part                      VARCHAR(1) NOT NULL,
    vendor                    TEXT NOT NULL,
    product                   TEXT NOT NULL,
    criteria                  TEXT NOT NULL,
    vulnerable                BOOLEAN NOT NULL DEFAULT true,
    version_start_including   TEXT,
    version_start_excluding   TEXT,
    version_end_including     TEXT,
    version_end_excluding     TEXT
);
-- Same shape as idx_cpe_dictionary_vendor_product (V31) -- an exact (vendor, product) equality
-- lookup is the expected read pattern once this table gets a consumer.
CREATE INDEX idx_nvd_cve_cpe_match_vendor_product ON nvd_cve_cpe_match (vendor, product);
CREATE INDEX idx_nvd_cve_cpe_match_cve_id ON nvd_cve_cpe_match (cve_id);
