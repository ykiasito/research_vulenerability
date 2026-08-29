-- V1__init.sql
-- Initial schema for the software vulnerability research server.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- users -----------------------------------------------------------------
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- user_secrets ------------------------------------------------------------
-- Per-user API keys (Claude, NVD, ...), encrypted at the application layer.
CREATE TABLE user_secrets (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider      VARCHAR(50) NOT NULL CHECK (provider IN ('claude', 'nvd')),
    encrypted_key TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_user_secrets_user_provider UNIQUE (user_id, provider)
);

-- research_jobs -----------------------------------------------------------
CREATE TABLE research_jobs (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csv_filename  VARCHAR(255) NOT NULL,
    status        VARCHAR(50) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ
);

-- research_job_items -------------------------------------------------------
CREATE TABLE research_job_items (
    id            BIGSERIAL PRIMARY KEY,
    job_id        BIGINT NOT NULL REFERENCES research_jobs (id) ON DELETE CASCADE,
    product_name  VARCHAR(255) NOT NULL,
    version       VARCHAR(100) NOT NULL,
    vendor        VARCHAR(255),
    usage_text    TEXT NOT NULL,
    install_url   TEXT,
    status        VARCHAR(50) NOT NULL
);

-- identified_products -------------------------------------------------------
CREATE TABLE identified_products (
    id            BIGSERIAL PRIMARY KEY,
    job_item_id   BIGINT NOT NULL REFERENCES research_job_items (id) ON DELETE CASCADE,
    ecosystem     VARCHAR(100),
    package_name  VARCHAR(255),
    cpe           TEXT,
    purl          TEXT,
    confidence    NUMERIC,
    method        VARCHAR(20) NOT NULL
);

-- vulnerabilities -------------------------------------------------------
CREATE TABLE vulnerabilities (
    id              BIGSERIAL PRIMARY KEY,
    cve_or_ghsa_id  VARCHAR(100) NOT NULL UNIQUE,
    source          VARCHAR(50) NOT NULL,
    severity        VARCHAR(20),
    description     TEXT,
    url             TEXT
);

-- job_item_vulnerabilities -------------------------------------------------
CREATE TABLE job_item_vulnerabilities (
    job_item_id           BIGINT NOT NULL REFERENCES research_job_items (id) ON DELETE CASCADE,
    vulnerability_id      BIGINT NOT NULL REFERENCES vulnerabilities (id) ON DELETE CASCADE,
    discovered_via_tier   VARCHAR(50) NOT NULL,
    citation_url          TEXT,
    PRIMARY KEY (job_item_id, vulnerability_id)
);

-- cpe_dictionary ------------------------------------------------------------
-- Local mirror of the NVD CPE Dictionary, refreshed periodically, used for
-- fuzzy matching via pg_trgm.
CREATE TABLE cpe_dictionary (
    id              BIGSERIAL PRIMARY KEY,
    cpe_string      TEXT NOT NULL,
    title           TEXT,
    vendor          TEXT,
    product         TEXT,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_cpe_dictionary_product_trgm
    ON cpe_dictionary USING GIN (product gin_trgm_ops);

CREATE INDEX idx_cpe_dictionary_title_trgm
    ON cpe_dictionary USING GIN (title gin_trgm_ops);

-- vendor_advisory_sources ----------------------------------------------------
CREATE TABLE vendor_advisory_sources (
    id            BIGSERIAL PRIMARY KEY,
    vendor_name   VARCHAR(255) NOT NULL UNIQUE,
    feed_type     VARCHAR(20) NOT NULL CHECK (feed_type IN ('csaf', 'rss', 'scrape')),
    url           TEXT NOT NULL
);
