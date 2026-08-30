-- V8__cve_org.sql
-- Local mirror of CVE.org's CVE List V5 (https://github.com/CVEProject/cvelistV5), synced via
-- CveOrgSyncService. cve_org_records holds one row per CVE record (raw JSON kept for the
-- affected-version-range check done at query time); cve_org_affected_products is a flattened,
-- pg_trgm-searchable index of each record's affected[].vendor/product/packageName entries, mirroring
-- the cpe_dictionary fuzzy-match pattern already used for NVD's CPE Dictionary.

CREATE TABLE cve_org_records (
    cve_id          VARCHAR(30) PRIMARY KEY,
    title           TEXT,
    description     TEXT,
    cvss_score      NUMERIC,
    cvss_severity   VARCHAR(20),
    state           VARCHAR(20),
    date_published  TIMESTAMPTZ,
    date_updated    TIMESTAMPTZ,
    raw_json        TEXT NOT NULL,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cve_org_affected_products (
    id           BIGSERIAL PRIMARY KEY,
    cve_id       VARCHAR(30) NOT NULL REFERENCES cve_org_records(cve_id) ON DELETE CASCADE,
    vendor       TEXT,
    product      TEXT,
    package_name TEXT
);

CREATE INDEX idx_cve_org_affected_cve_id ON cve_org_affected_products (cve_id);
CREATE INDEX idx_cve_org_affected_vendor_trgm ON cve_org_affected_products USING gin (vendor gin_trgm_ops);
CREATE INDEX idx_cve_org_affected_product_trgm ON cve_org_affected_products USING gin (product gin_trgm_ops);

-- Single-row table tracking sync progress, so the daily delta sync knows the last GitHub release
-- tag it already applied and whether a full baseline has ever been loaded.
CREATE TABLE cve_org_sync_state (
    id                SMALLINT PRIMARY KEY DEFAULT 1,
    baseline_loaded   BOOLEAN NOT NULL DEFAULT false,
    last_release_tag  VARCHAR(100),
    last_synced_at    TIMESTAMPTZ,
    CHECK (id = 1)
);
INSERT INTO cve_org_sync_state (id) VALUES (1);
