-- V18__csaf_product_status_unique.sql
-- REVISE item 6 (senior review 2026-08-27): when several ORIGINAL product_ids in an advisory's
-- product_tree fold to the same canonical product (CsafProductTreeWalker's architecture-variant
-- folding — see its class javadoc), and the advisory lists more than one of those original ids under
-- the same product_status/CVE, CsafDocumentUpsertService could previously write duplicate identical
-- (vendor, advisory_id, cve_id, csaf_product_id, status) rows into csaf_product_status. The
-- application now dedupes within the upsert loop itself; this constraint enforces the same invariant
-- at the DB level so it holds even if the application-level dedup is ever bypassed or regresses.
ALTER TABLE csaf_product_status
    ADD CONSTRAINT uq_csaf_product_status_vendor_advisory_cve_product_status
    UNIQUE (vendor, advisory_id, cve_id, csaf_product_id, status);
