-- V21__csaf_redhat_revise_fixes.sql
-- CSAF Phase 2 (Red Hat) senior-reviewer REVISE pass (2026-08-27) — re-ran the go/no-go review's own
-- measurements against the real 27,930-document archive and found two critical correctness bugs plus
-- several performance/hygiene items. This migration covers the two schema-level fixes (items 1 and 5
-- of the REVISE list); see CsafProductRepositoryImpl/CsafVulnerabilitySource for the corresponding
-- application-code fixes.

-- item 1 (CRITICAL): findCandidateProductsExact had LIMIT 30 with no ORDER BY — ties broke on
-- physical row order (roughly year-ascending, tar-walk/insertion order), so a query for a common name
-- like 'kernel' (5,514 matching rows) returned RHSA-1999:1..30 and NEVER anything recent. Denormalizing
-- the parent advisory's date_updated onto csaf_products lets the primary equality path order by
-- recency without a join — measured by the reviewer at ~1.0ms this way vs ~16.8ms for a join-based
-- alternative. Populated at ingest time by CsafDocumentUpsertService; NULL for any pre-existing row
-- until its advisory is next re-synced (harmless — NULLS LAST just sorts those behind everything with
-- a real timestamp, never crashes the query).
ALTER TABLE csaf_products ADD COLUMN advisory_updated_at TIMESTAMPTZ;

-- Replaces V20's (vendor, component_name_normalized) index — every real query through this index also
-- wants ORDER BY advisory_updated_at DESC, and a composite index serves the plain equality lookup just
-- as well as the narrower one did (leftmost-prefix), so the old index is now redundant.
DROP INDEX idx_csaf_products_component_name_normalized;
CREATE INDEX idx_csaf_products_component_name_normalized_updated
    ON csaf_products (vendor, component_name_normalized, advisory_updated_at DESC);

-- item 5: the trgm fuzzy fallback (CsafProductRepositoryImpl#findCandidateProducts) is, by
-- construction, only ever reached for Siemens now — Red Hat's purl-derived names are always found via
-- the item-1 equality path when a match exists at all (measured: only 9.2% of real product names hit
-- the equality path, the rest correctly find nothing and would otherwise scan 1.75M+ Red Hat rows for
-- no benefit). A partial GIN index scoped to vendor='siemens' matches the query's own new WHERE clause
-- exactly, dropping a Red Hat miss-case query from 23.3ms to 0.14ms in the reviewer's measurement
-- while leaving Siemens' own hit-case cost unchanged.
DROP INDEX idx_csaf_products_component_name_trgm;
CREATE INDEX idx_csaf_products_component_name_trgm_siemens
    ON csaf_products USING gin (component_name gin_trgm_ops) WHERE vendor = 'siemens';
