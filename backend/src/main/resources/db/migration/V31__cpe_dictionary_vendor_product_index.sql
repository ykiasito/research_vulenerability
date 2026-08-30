-- V31__cpe_dictionary_vendor_product_index.sql
-- PR #14 REVISE (senior review, 2026-08-30): CpeDictionaryRepositoryImpl#collect now re-derives
-- target_sw_values/max_cataloged_major via a CROSS JOIN LATERAL that looks each of the (at most
-- `limit`, currently 40) rows the trigram-filtered subquery already narrowed down to back up in
-- cpe_dictionary by an exact (vendor, product) equality join -- see that method's own comment for
-- why "=" is used instead of "IS NOT DISTINCT FROM". Without this index, each of those LATERAL
-- lookups would fall back to a sequential scan; with it, the plain "=" join can use a btree index
-- scan directly (an "IS NOT DISTINCT FROM" join could not).
CREATE INDEX idx_cpe_dictionary_vendor_product
    ON cpe_dictionary (vendor, product);
