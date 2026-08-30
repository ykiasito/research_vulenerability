-- V17__csaf_vendor_advisories.sql
-- Local mirror of vendor-published CSAF (Common Security Advisory Framework) security advisories —
-- see docs/spec/csaf-vendor-advisory-plan.md §3 for the full design rationale (4-table shape chosen
-- over an earlier 2-table draft specifically because CSAF's applicability status is keyed by
-- (vulnerability, product), not (advisory, product) — a single advisory commonly bundles many CVEs
-- with different per-product statuses). Phase 1 (this migration) only populates 'siemens' rows via
-- SiemensCsafSyncService; the schema itself is vendor-agnostic so a future RedHatCsafSyncService can
-- reuse it unchanged (plan §4).

-- One row per advisory document. raw_json is kept for re-derivation/debugging only — the find()-time
-- query path (CsafVulnerabilitySource) never parses it; csaf_products/csaf_product_status are the
-- only structures queried at request time.
CREATE TABLE csaf_advisories (
    vendor          VARCHAR(50) NOT NULL,    -- 'siemens' | (future) 'redhat' | 'cisco'
    tracking_id     VARCHAR(100) NOT NULL,   -- CSAF tracking.id (e.g. SSA-434797, RHSA-2026:1234)
    tracking_status VARCHAR(20) NOT NULL,    -- 'draft' | 'interim' | 'final' — only 'final' advisories
                                              -- ever surface as a finding/annotation (plan §7)
    revision        VARCHAR(50),             -- tracking.version, vendor-specific free-text semantics
    title           TEXT,
    tlp_label       VARCHAR(20),             -- distribution.tlp.label
    cvss_score      NUMERIC,
    cvss_severity   VARCHAR(20),
    date_published  TIMESTAMPTZ,
    date_updated    TIMESTAMPTZ,
    raw_json        TEXT NOT NULL,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vendor, tracking_id)
);

-- One row per distinct resolved product in an advisory's product_tree (CsafProductTreeWalker's
-- output — architecture-only variants folded into a single row, see the walker's javadoc).
-- platform_name is non-NULL only for a product resolved from product_tree.relationships[] (a
-- component-of-platform combination, e.g. "openssl" component_name with platform_name "Red Hat
-- Enterprise Linux 9").
CREATE TABLE csaf_products (
    id                  BIGSERIAL PRIMARY KEY,
    vendor              VARCHAR(50) NOT NULL,
    advisory_id         VARCHAR(100) NOT NULL,
    csaf_product_id     TEXT NOT NULL,
    component_name      TEXT,
    component_version   TEXT,
    platform_name       TEXT,
    cpe                 TEXT,
    purl                TEXT,
    UNIQUE (vendor, advisory_id, csaf_product_id),
    FOREIGN KEY (vendor, advisory_id) REFERENCES csaf_advisories (vendor, tracking_id) ON DELETE CASCADE
);

CREATE INDEX idx_csaf_products_advisory ON csaf_products (vendor, advisory_id);
-- component_name only — platform_name (e.g. "Red Hat Enterprise Linux 9") repeats across huge
-- numbers of rows and would be a low-selectivity index nothing queries by (plan §3).
CREATE INDEX idx_csaf_products_component_name_trgm ON csaf_products USING gin (component_name gin_trgm_ops);

-- The (vulnerability x product) matrix itself — replaces the earlier draft's single per-advisory
-- status column, which couldn't represent one advisory bundling several CVEs with different
-- per-product statuses (plan §3).
CREATE TABLE csaf_product_status (
    id                  BIGSERIAL PRIMARY KEY,
    vendor              VARCHAR(50) NOT NULL,
    advisory_id         VARCHAR(100) NOT NULL,
    cve_id              VARCHAR(50) NOT NULL,
    csaf_product_id     TEXT NOT NULL,
    status              VARCHAR(30) NOT NULL,  -- 'fixed' | 'known_affected' | 'known_not_affected' | 'under_investigation'
    fixed_version       TEXT,                  -- vendor-native version/remediation text (often not
                                                 -- semver — never copy into vulnerabilities.fixed_version)
    remediation_url     TEXT,
    FOREIGN KEY (vendor, advisory_id) REFERENCES csaf_advisories (vendor, tracking_id) ON DELETE CASCADE,
    FOREIGN KEY (vendor, advisory_id, csaf_product_id)
        REFERENCES csaf_products (vendor, advisory_id, csaf_product_id) ON DELETE CASCADE
);

CREATE INDEX idx_csaf_product_status_cve ON csaf_product_status (vendor, cve_id);
CREATE INDEX idx_csaf_product_status_advisory_product ON csaf_product_status (vendor, advisory_id, csaf_product_id);

-- Per-vendor sync progress/cursor — a multi-row table (unlike cve_org_sync_state's single row)
-- since each vendor's sync service is independent and one vendor's failure must not affect another's
-- recorded progress (plan §3).
CREATE TABLE csaf_sync_state (
    vendor            VARCHAR(50) PRIMARY KEY,
    last_synced_at    TIMESTAMPTZ,
    last_cursor       TEXT   -- Siemens: last-processed ROLIE entry `updated` timestamp (ISO-8601 text,
                              -- ascending-processed per plan §7)
);

-- job_item_vulnerabilities gets the CSAF annotation columns (plan §8-2) — same shape/precedent as
-- V16's bundled_component_name/bundled_component_version: non-NULL only on the row(s) a CSAF
-- advisory actually annotated. Unlike the bundled-component case, a CSAF annotation is usually
-- attached to a row ALREADY created by another source (NVD/OSV/CVE.org) for the same CVE — see
-- Stage2VulnerabilityResearchService's two-pass handling of CsafVulnerabilitySource's results.
ALTER TABLE job_item_vulnerabilities ADD COLUMN csaf_advisory_id VARCHAR(100);
ALTER TABLE job_item_vulnerabilities ADD COLUMN csaf_status VARCHAR(30);
ALTER TABLE job_item_vulnerabilities ADD COLUMN csaf_fixed_version TEXT;
