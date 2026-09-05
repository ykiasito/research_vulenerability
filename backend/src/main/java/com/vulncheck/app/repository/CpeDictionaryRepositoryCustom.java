package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.util.List;

public interface CpeDictionaryRepositoryCustom {

    /** Fuzzy-matches {@code productQuery} against the product/title columns using pg_trgm
     *  similarity, via each column's GIN trigram index (see the {@code Impl} class for why this
     *  can't just be a {@code similarity(col, x) > threshold} native {@code @Query}). Two separate
     *  thresholds because the two columns behave very differently: {@code product} is a normalized
     *  single-word slug where a real match scores ~1.0, while {@code title} is a full
     *  human-readable string whose similarity to a short query can be inflated just by sharing a
     *  vendor word (e.g. "Microsoft Edge" vs. "Microsoft NuGet 4.3.1") — so a title-only hit needs
     *  a much higher bar than a product-slug hit to avoid false positives. */
    List<CpeDictionaryEntry> findFuzzyMatches(String productQuery, double productThreshold, double titleThreshold, int limit);

    /** Bulk upsert for the full-dictionary sync. The per-row {@code upsert} is fine for the handful
     *  of rows a live single-page lookup returns, but the full NVD dictionary is ~1.8M rows — one
     *  statement per row turns that into hours of pure round-trip overhead, so the paginating sync
     *  writes a page at a time through a single batched statement instead. */
    void upsertBatch(List<CpeDictionaryEntry> entries);

    /**
     * Left-anchored regex search against the {@code product} column, backing the
     * initialism-expansion direction of short-form/long-form name matching ({@code
     * Stage1IdentificationService#expandLeadingInitialism}), which pg_trgm similarity cannot find
     * at all: measured live 2026-08-25, {@code similarity('visual_studio_code', 'code')} is 0.26,
     * under the 0.3 product threshold, so a plain fuzzy search for the query's anchor word never
     * surfaces the long-form candidate in the first place.
     *
     * <p>Builds the regex directly from the abbreviation's own letters plus the literal anchor —
     * e.g. abbreviation {@code "vs"} + anchor {@code "code"} builds {@code
     * ^v[^_]*_s[^_]*_code(_|$)} — so the SQL {@code WHERE} clause itself does the real filtering (a
     * candidate must have exactly the abbreviation's letters as its leading per-word initials,
     * immediately followed by the literal anchor at a word boundary or end of slug) instead of a
     * broad {@code ILIKE '%anchor%'} pre-filter that only {@code limit} narrowed down after the
     * fact — measured live 2026-08-25 (senior review): that pre-filter shape let the row cap catch
     * only whatever the DB's arbitrary {@code ORDER BY length(product)} happened to put first, e.g.
     * only ~1/3 of a 1551-row "manager"-anchor population fit inside a 500-row window at all, with
     * no guarantee the real match was among them.
     *
     * <p>Confirmed via {@code EXPLAIN ANALYZE} against the real 1.8M-row dictionary (2026-08-25)
     * that this still uses the existing {@code idx_cpe_dictionary_product_trgm} GIN trigram index
     * (pg_trgm supports index-accelerated regex search via {@code ~}, not just LIKE/similarity) —
     * ~13ms for a real anchor — as long as the anchor is at least 3 characters; below that the
     * planner has no extractable trigram from the regex and falls back to a measured 230ms-1.4s
     * sequential-scan-shaped bitmap scan (see {@code
     * Stage1IdentificationService#expandLeadingInitialism}'s own anchor-length guard). The caller
     * still applies its own {@code leadingInitialsMatch} post-check afterward as a safety net, since
     * the SQL regex alone can't fully replicate every token-boundary edge case.
     */
    List<CpeDictionaryEntry> findByLeadingInitialismMatch(String abbreviation, String anchor, int limit);

    /**
     * Exact-match lookup against the {@code (vendor, product)} composite btree index ({@code
     * idx_cpe_dictionary_vendor_product}, see {@code V31__cpe_dictionary_vendor_product_index.sql}),
     * backing item 302's candidate-pool fallback in {@code
     * Stage1IdentificationService#exactVendorProductMatches} (called from {@code
     * Stage1IdentificationService#resolveCpeCandidates}, not {@code localCpeLookup} — see that
     * method's own javadoc for why).
     *
     * <p>Why exact match rather than a lower pg_trgm similarity threshold — same reasoning as {@link
     * #findByLeadingInitialismMatch}'s own javadoc (short dictionary slugs are structurally
     * disadvantaged against a longer query string): measured live 2026-09-05, {@code
     * similarity('falcon', 'CrowdStrike Falcon Sensor')} = 0.269 (under the 0.3 product threshold) and
     * {@code similarity('CrowdStrike Falcon 6.42.15610', 'CrowdStrike Falcon Sensor')} = 0.51 (under
     * the 0.6 title threshold), so {@code crowdstrike:falcon} never enters the trigram-ranked
     * candidate pool at all no matter how the rest of the ranking is tuned. Unlike lowering the
     * thresholds (rejected by senior review — risks breaking the GIN index's own pre-filter
     * selectivity and the downstream K1/K2/K3 ranking constants tuned against the current thresholds),
     * this adds a second, independent retrieval path rather than touching the existing one at all: an
     * exact {@code (vendor, product)} equality match needs no similarity score to be trustworthy in
     * the first place.
     *
     * <p>{@code pairs} must be empty-safe (returns an empty list, no query issued) and is always
     * passed as JDBC bind parameters, never string-interpolated — see the {@code Impl} class for the
     * bounded pair-generation caveat this depends on ({@code product} is {@code VARCHAR(255)}, so an
     * unbounded token cross-product could otherwise reach tens of thousands of pairs).
     */
    List<CpeDictionaryEntry> findByVendorProductPairs(List<VendorProductPair> pairs, int limit);

    /**
     * One candidate {@code (vendor, product)} slug pair for {@link #findByVendorProductPairs}.
     * Deliberately a bare pair of normalized single-word tokens (not underscore-joined multi-word
     * slugs like the dictionary's own {@code product} column can hold, e.g. {@code
     * visual_studio_code}) — {@code Stage1IdentificationService} builds these from the plain
     * cross-product of the item's own tokenized vendor/product-name words, which is exactly the
     * shape a single-word dictionary slug like {@code falcon} needs to match on, not a broader
     * name-variant search (that's a separate, already-existing fallback — see {@code
     * Stage1IdentificationService#findByNameVariants}).
     */
    record VendorProductPair(String vendor, String product) {
    }
}
