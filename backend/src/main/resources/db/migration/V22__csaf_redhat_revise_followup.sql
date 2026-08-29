-- V22__csaf_redhat_revise_followup.sql
-- Senior-reviewer go/no-go follow-up on V21's REVISE fixes (2026-08-27) — two concrete defects found
-- in V21 itself. V21 is already applied to the live database (flyway_schema_history installed_rank
-- 21) so it must not be edited (checksum validation would break app boot); both fixes land here
-- instead.

-- Fix 1: V21's advisory_updated_at is only populated at INSERT time going forward (by
-- CsafDocumentUpsertService) — any csaf_products row that existed before V21 was applied stays NULL
-- forever, which means it always sorts last (NULLS LAST) in CsafProductRepositoryImpl's recency
-- ordering, defeating REVISE item 1 for every pre-existing row until its advisory happens to be
-- re-synced. Backfill from the parent advisory's own date_updated (same join key V21's column
-- denormalizes: (vendor, advisory_id) on csaf_products <-> (vendor, tracking_id) on csaf_advisories,
-- per V17's schema).
UPDATE csaf_products p
SET advisory_updated_at = a.date_updated
FROM csaf_advisories a
WHERE a.vendor = p.vendor AND a.tracking_id = p.advisory_id
  AND p.advisory_updated_at IS NULL;

-- Fix 2: V21's index ordered advisory_updated_at DESC, which Postgres defaults to NULLS FIRST for a
-- descending index column — but CsafProductRepositoryImpl's actual query (both
-- findCandidateProductsExact and findCandidateProducts) orders DESC NULLS LAST. The mismatch means
-- the index can't satisfy the query's ORDER BY, so Postgres falls back to a full matching-row fetch
-- + sort, silently defeating REVISE item 1's whole performance point. Rebuild the index with an
-- explicit NULLS LAST to match the query exactly.
DROP INDEX idx_csaf_products_component_name_normalized_updated;
CREATE INDEX idx_csaf_products_component_name_normalized_updated
    ON csaf_products (vendor, component_name_normalized, advisory_updated_at DESC NULLS LAST);
