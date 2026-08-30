-- V20__csaf_redhat_support.sql
-- CSAF Phase 2 (Red Hat) go/no-go review, items 2 and 4 — see
-- docs/spec/csaf-vendor-advisory-plan.md §10 and CsafProductTreeWalker/CsafProductRepositoryImpl's
-- own javadoc for the full rationale. V17's schema is otherwise reused as-is for Red Hat (it was
-- already vendor-agnostic by design) — this migration only adds what the review's measured findings
-- required.

-- item 2: CsafProductTreeWalker now derives component_name/component_version from a product's purl
-- when present (fixes a real bug: for Red Hat's RPM-shaped leaves, the un-derived raw leaf name is
-- the full NEVRA string, e.g. "openssl-1:3.0.7-24.el9_2.x86_64", which fails to fuzzy-match a CSV
-- row for "openssl" — measured similarity 0.258, below this app's 0.35 threshold). The original raw
-- leaf name is preserved here purely for debugging/display; matching never reads this column.
ALTER TABLE csaf_products ADD COLUMN raw_leaf_name TEXT;

-- item 4: the existing candidate query (component_name % ?, a pg_trgm GIN-indexed fuzzy match) is
-- kept as a fallback, but a purl-derived name is usually already an EXACT, clean package name (e.g.
-- "openssl") — an equality lookup on it should be the primary match path. Measured against the real
-- trgm query at ~3.8M rows: 6,835ms/lookup, which would break this project's 1,000-items/3-hours
-- throughput target by itself. A generated column (rather than maintaining a duplicate value from
-- the application) keeps this in sync automatically with component_name and is excluded from
-- ordinary INSERT column lists, so CsafProductRepositoryImpl's batch insert needs no changes to
-- populate it.
ALTER TABLE csaf_products
    ADD COLUMN component_name_normalized TEXT
    GENERATED ALWAYS AS (lower(btrim(component_name))) STORED;

-- (vendor, component_name_normalized) — not component_name_normalized alone — since every real
-- query scopes by vendor first (CsafVulnerabilitySource's WHERE vendor IN (...)); see
-- CsafProductRepositoryImpl's javadoc for the EXPLAIN ANALYZE plan/timing this index produces.
CREATE INDEX idx_csaf_products_component_name_normalized ON csaf_products (vendor, component_name_normalized);
