-- V13__backfill_corrupted_cpe_vendor_product.sql
-- One-shot backfill for cpe_dictionary rows whose vendor/product columns were computed by the OLD
-- naive CPE splitter, before com.vulncheck.app.service.nvd.CpeUtils#parseVendorProduct's
-- escape-aware fix existed (senior review, job 37 root-cause). A plain split(":") mis-indexes any
-- CPE string containing an escaped colon within a segment, e.g. Perl's HTTP::Session module
-- cpe:2.3:a:ktat:http\:\:session:0.41:*:*:*:*:perl:*:* naive-split into product="http\" (a
-- trailing-backslash artifact) instead of the correct "http\:\:session". Downstream normalization
-- strips that artifact down to exactly "http", handing this (and 107 other affected products —
-- 4,815 rows total, measured 2026-08-26) an undeserved top-tier exact-match rank in
-- Stage1IdentificationService's candidate ranking — this is what let ktat:http\::session
-- masquerade as crates.io's http package ahead of the real hyper:http.
--
-- This is a targeted UPDATE against the existing ~1.8M-row table, NOT a full NVD resync (a full
-- resync takes ~103 minutes per this project's own history and would be wildly disproportionate to
-- fixing 4,815 already-present rows' derived columns from their own already-correct cpe_string).
--
-- Every corrupted row has this same fingerprint: product ends in a literal trailing backslash,
-- since the naive splitter always stopped at the FIRST colon inside the escaped sequence, only ever
-- capturing "...\<end-of-token>" going into the product column. Recomputes vendor/product from each
-- affected row's own cpe_string using the same escape-aware colon-splitting semantics as CpeUtils
-- #parseVendorProduct (a migration can't call application code, so the algorithm is mirrored here in
-- plpgsql — walk the string once, treating a backslash-prefixed character as always non-delimiting,
-- exactly like CpeUtils's own char-by-char loop).

CREATE FUNCTION pg_temp_cpe_split_escape_aware(cpe_string text) RETURNS text[] AS $$
DECLARE
    segments text[] := ARRAY[]::text[];
    current_segment text := '';
    i int := 1;
    len int := length(cpe_string);
    c text;
BEGIN
    WHILE i <= len LOOP
        c := substr(cpe_string, i, 1);
        IF c = chr(92) AND i < len THEN
            -- Backslash-prefixed character: always part of the current segment, never a delimiter
            -- (mirrors CpeUtils.splitCpeSegments appending both chars and skipping ahead by 2).
            current_segment := current_segment || c || substr(cpe_string, i + 1, 1);
            i := i + 2;
        ELSIF c = ':' THEN
            segments := array_append(segments, current_segment);
            current_segment := '';
            i := i + 1;
        ELSE
            current_segment := current_segment || c;
            i := i + 1;
        END IF;
    END LOOP;
    segments := array_append(segments, current_segment);
    RETURN segments;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Fingerprint of a naive-splitter-corrupted row: product ends in the trailing-backslash artifact.
-- Avoids relying on LIKE's escape-char handling for a literal backslash (fiddly and easy to get
-- subtly wrong across client/psql layers) in favor of an unambiguous chr(92) comparison.
UPDATE cpe_dictionary
SET vendor = (pg_temp_cpe_split_escape_aware(cpe_string))[4],
    product = (pg_temp_cpe_split_escape_aware(cpe_string))[5]
WHERE right(product, 1) = chr(92);

DROP FUNCTION pg_temp_cpe_split_escape_aware(text);
