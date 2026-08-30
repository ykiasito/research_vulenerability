-- V9__trgm_query_performance.sql
-- cve_org_affected_products.package_name was searched by Stage2's fuzzy match but never had its
-- own trigram index (only vendor and product did) — adding it now that the query is being
-- rewritten to actually use these indexes (see CpeDictionaryRepositoryImpl /
-- CveOrgAffectedProductRepositoryImpl: the previous `similarity(col, x) > threshold` query shape
-- could never use a GIN trgm index at all, confirmed via EXPLAIN — only the `%` operator can).
CREATE INDEX idx_cve_org_affected_package_name_trgm
    ON cve_org_affected_products USING gin (package_name gin_trgm_ops);
